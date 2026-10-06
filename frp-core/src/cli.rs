//! CLI argument parsing for frps and frpc binaries.
//!
//! Uses bpaf combinators for the frps and frpc CLI surfaces.
//! All flags accept both hyphen (`--log-file`) and underscore (`--log_file`) forms.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::time::Duration;

use bpaf::Parser;
use bpaf::*;
// `bpaf::*` re-exports the combinator functions but not this builder type, which
// [`go_bool_named`] returns.
use bpaf::parsers::NamedArg;

/// Parse a bool flag value with Go `strconv.ParseBool` spellings.
///
/// The **adjacent** form (`--strict-config=false`) matches Go pflag. The
/// **space-separated** form (`--strict-config false`) is an frp-rs extension,
/// **not** Go pflag semantics: measured on Go v0.71.0,
/// `frpc reload --strict-config false -c <unknown-key config>` prints
/// `json: unknown field "notAKnownFrpKey"` (strict stays `true`; the token is an
/// unused positional for the subcommands and `unknown command "false"` for the
/// root commands `frpc`/`frps`), while frp-rs consumes the value as `false` and
/// proceeds. The same holds for `--strict-config foo`, where Go ignores the
/// token and frp-rs rejects it. The divergence is recorded in `TODO.md`.
///
/// That extension is **kept, documented and made loud**, not dropped: the
/// measured table, the measured drop branch, and the reason live in
/// `docs/developing.md` § "`--strict-config`: the space-separated value form";
/// every parser below states the extension in its `--help` through
/// [`strict_config_parser`], and
/// [`STRICT_CONFIG_SPACE_FORM_WARNING`] is printed on stderr whenever the space
/// form is actually consumed, so the divergence cannot bite silently.
///
/// Note the error string below is never user-visible: bpaf backtracks from this
/// parser on `Err` and the leftover token is then reported as
/// `` `<value>` is not expected in this context `` (measured for
/// `--strict-config foo`, `--strict-config ""` and `--strict-config=foo`).
/// The value only has to signal failure.
fn parse_go_bool(value: String) -> Result<bool, String> {
    match value.as_str() {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!("invalid boolean value \"{value}\"")),
    }
}

/// The one stderr line printed when the space-separated `--strict-config <bool>`
/// extension is consumed. Deliberately a single line, on the path only, so a
/// script that pipes stderr still sees it and a Go-faithful invocation stays
/// silent.
pub const STRICT_CONFIG_SPACE_FORM_WARNING: &str = "warning: --strict-config <bool> is an frp-rs extension; Go's pflag does not consume the token and stays strict. Use --strict-config=<bool> for identical behaviour.";

/// Help for the `=BOOL` form (Go-faithful), used by [`strict_config_parser`].
///
/// Kept as a `const` so the test can pin each entry separately: the bare-form
/// help also contains `--strict-config=<bool>`, so a substring assertion on the
/// rendered help alone cannot tell a deleted value help from a present one.
const STRICT_CONFIG_VALUE_HELP: &str = "Strict config parsing mode: true or false. The Go-faithful value spelling is --strict-config=<bool>";

/// Help for the bare `--strict-config` switch (Go-faithful) plus the extension
/// statement. See [`STRICT_CONFIG_VALUE_HELP`] for why these are `const`s.
const STRICT_CONFIG_SWITCH_HELP: &str = "Strict config parsing mode, unknown fields cause an error (default true). The Go-faithful spellings are this bare flag (=true) and --strict-config=<bool>; frp-rs additionally consumes a space-separated --strict-config <bool> as the value, which Go's pflag does not. A warning is printed when that extension is used";

/// True when `argv` contains the frp-rs space-separated extension in the one
/// shape frp-rs actually consumes it: a `--strict-config`/`--strict_config`
/// token immediately followed by a token that is a value under Go's
/// `strconv.ParseBool` grammar and is not `-`-prefixed.
///
/// This mirrors bpaf exactly, which is what makes the warning safe to key off
/// argv rather than off the parser:
///
/// * the `=` spelling (`--strict-config=false`) is a **single** argv token, so
///   it never matches the `--strict-config` / `--strict_config` equality test —
///   the Go-faithful spelling stays silent;
/// * a bare `--strict-config` followed by another flag (`--strict-config
///   --config x`) is not matched, because bpaf's `argument` never consumes a
///   `-`-prefixed token as a value — the switch still yields `true` silently;
/// * a non-bool token (`foo`, `""`) is not matched, and does not need to be:
///   the parse fails there, so no value was consumed and the process exits
///   before any command runs.
///
/// The caller prints the warning only after the command parsed successfully, so
/// a failing argv never produces a warning either.
fn strict_config_space_form_used(argv: &[OsString]) -> bool {
    argv.windows(2).any(|pair| {
        (pair[0] == "--strict-config" || pair[0] == "--strict_config")
            && pair[1].to_str().is_some_and(|value| {
                !value.starts_with('-') && parse_go_bool(value.to_string()).is_ok()
            })
    })
}

/// Print [`STRICT_CONFIG_SPACE_FORM_WARNING`] once if `argv` used the extension.
fn warn_if_strict_config_space_form_used(argv: &[OsString]) {
    if strict_config_space_form_used(argv) {
        eprintln!("{STRICT_CONFIG_SPACE_FORM_WARNING}");
    }
}

/// The single `--strict-config`/`--strict_config` parser shared by `frps` and
/// every `frpc` parser that accepts the flag (`run`, `verify`, `reload`,
/// `status`, `stop`).
///
/// Go frp v0.71.0 registers it as a pflag **bool** (both binaries — measured,
/// the flag is in `frps --help` and `frpc --help`; Go's own text is `strict
/// config parsing mode, unknown fields will cause an errors (default true)` on
/// `frpc` and `… will cause errors …` on `frps`), and a pflag bool never
/// consumes a following token. frp-rs accepts two value spellings; the `=` one
/// is Go-faithful, the space-separated one is the documented extension:
///
/// * bare `--strict-config` → `true` (Go-faithful);
/// * `--strict-config=<bool>` → that value (Go-faithful);
/// * `--strict-config <bool>` → that value (**frp-rs extension**; Go leaves the
///   token as a positional argument and strict stays `true`);
/// * absent → `true` (Go-faithful).
///
/// A non-bool token is rejected in both spellings (`Error: \`foo\` is not
/// expected in this context`, exit 1). Go ignores the space-separated one and
/// parses the adjacent one with `strconv.ParseBool`; the three measured
/// outcomes and their messages are tabulated in `docs/developing.md`.
///
/// `or_else` picks the branch that consumes more arguments, so the value form
/// wins whenever a value is present, while the bare form falls back to the
/// switch (which yields `true` both when present and absent). A plain
/// `.switch()` cannot parse a value (audit task 9 finding 3). bpaf's `argument`
/// never consumes a `-`-prefixed token as a value, so `--strict-config --config
/// x` still lands on the switch.
fn strict_config_parser() -> impl Parser<bool> {
    let strict_value = long("strict-config")
        .long("strict_config")
        .help(STRICT_CONFIG_VALUE_HELP)
        .argument::<String>("BOOL")
        .parse(parse_go_bool);
    let strict_switch = long("strict-config")
        .long("strict_config")
        .help(STRICT_CONFIG_SWITCH_HELP)
        .flag(true, true);
    construct!([strict_value, strict_switch])
}

/// The `NamedArg` behind both branches of [`go_bool_flag`]: one spelling list
/// (hyphen name, the underscore alias frp-rs has always accepted, and an
/// optional short) and one `help`, so the two branches cannot drift apart.
fn go_bool_named(
    name: &'static str,
    alias: Option<&'static str>,
    short: Option<char>,
    help: &'static str,
) -> NamedArg {
    let mut named = long(name);
    if let Some(alias) = alias {
        named = named.long(alias);
    }
    if let Some(short) = short {
        named = named.short(short);
    }
    named.help(help)
}

/// [`go_bool_named`] for a bool that frp-rs spells out but Go registers under a
/// short name (`--uc`/`--ue`): the aliases are appended as bpaf's hidden longs,
/// so only the first (`name`) is rendered while every spelling parses. The
/// string flags use the same pattern for `--custom-domain`/`--sd`/`--mux`/
/// `--tls-server-name`.
fn go_bool_named_with_aliases(
    name: &'static str,
    aliases: &'static [&'static str],
    short: Option<char>,
    help: &'static str,
) -> NamedArg {
    let mut named = long(name);
    for alias in aliases {
        named = named.long(alias);
    }
    if let Some(short) = short {
        named = named.short(short);
    }
    named.help(help)
}

/// A Go-parity bool flag: the generalisation of [`strict_config_parser`] to
/// every bool both binaries register.
///
/// Go registers these with pflag's bool machinery, which accepts three
/// spellings of one flag: the bare `--flag` (sets `true`), `--flag=true` and
/// `--flag=false`. The attached value goes through `strconv.ParseBool`
/// ([`parse_go_bool`]), so `1`/`0`/`t`/`f`/`T`/`F`/`TRUE`/`FALSE`/`True`/
/// `False` are accepted and anything else is
/// `Error: invalid argument "…" for "--flag" flag: strconv.ParseBool: …`.
/// A pflag bool **never consumes a following token**, so the space-separated
/// `--flag <bool>` is not a value there.
///
/// bpaf's `.switch()` implements only the first of those three, which is why
/// argv Go accepts exited 1 here with `` `<bool>` is not expected in this
/// context `` (`TODO.md:3498`). This expands to the `=BOOL` spelling with Go's
/// grammar, and deliberately does **not** add the space-separated form:
/// `.adjacent()` makes the value branch accept only `--flag=<value>`, so
/// `--flag <bool>` leaves the token unconsumed and is refused exactly as
/// before. That keeps this change to the spellings Go accepts — see
/// `docs/developing.md` § `--flag=<bool>` for the measured per-command Go
/// behaviour of the space form, which is *not* uniform (`frps --tls-only
/// false` is rc 1 `unknown command "false"`, while `frpc tcp --ue false` is
/// accepted and the token ignored) and is therefore recorded per flag rather
/// than papered over with a second extension.
///
/// The bare form keeps `.switch()`'s meaning: present → `true`, absent →
/// `false`.
///
/// A macro rather than a function because bpaf's `help` wants `&'static str`
/// and `concat!` is the only way to build the per-flag help while keeping the
/// flag name in the rendered text *derived from the name the parser registers*
/// — the help cannot end up naming a different flag.
macro_rules! go_bool_flag {
    ($name:literal, $alias:expr, $short:expr, $meaning:literal $(,)?) => {
        go_bool_flag_impl!(
            $name,
            $alias,
            $short,
            concat!(
                $meaning,
                ". The Go-faithful value spelling is --",
                $name,
                "=<bool>"
            ),
            concat!($meaning, " (bare form = true)")
        )
    };
}

/// [`go_bool_flag`] for a flag Go registers under a name frp-rs never
/// implemented: `$name` is Go's spelling and becomes the parser's **primary**
/// long (the only one bpaf renders), while `$aliases` are frp-rs's older
/// spellings kept as hidden aliases so existing command lines still parse.
macro_rules! go_bool_flag_with_aliases {
    ($name:literal, $aliases:expr, $short:expr, $meaning:literal $(,)?) => {{
        let value = go_bool_named_with_aliases(
            $name,
            $aliases,
            None,
            concat!(
                $meaning,
                ". The Go-faithful value spelling is --",
                $name,
                "=<bool>"
            ),
        )
        .argument::<String>("BOOL")
        .adjacent()
        .parse(parse_go_bool);
        let switch = go_bool_named_with_aliases(
            $name,
            $aliases,
            $short,
            concat!($meaning, " (bare form = true)"),
        )
        .flag(true, false);
        construct!([value, switch])
    }};
}

/// A flag frp-rs registers as a bool where **Go's flag of the same name is a
/// string**, so the help must not claim a Go bool it does not have. Go's own
/// grammar is wider and is measured in `docs/developing.md`; here only the
/// bool-shaped values are honoured.
macro_rules! go_bool_flag_go_string {
    ($name:literal, $alias:expr, $short:expr, $meaning:literal $(,)?) => {
        go_bool_flag_impl!(
            $name,
            $alias,
            $short,
            concat!(
                $meaning,
                ". frp-rs value spelling: --",
                $name,
                "=<bool>; Go's --",
                $name,
                " is a string flag and accepts any value there"
            ),
            concat!(
                $meaning,
                " (bare form = true); Go's --",
                $name,
                " is a string flag and consumes the next token"
            )
        )
    };
}

/// An frp-rs-only bool flag: same parsing and value grammar, but Go registers
/// no flag of this name, so the help must say so rather than claim parity.
macro_rules! go_bool_flag_rs_only {
    ($name:literal, $alias:expr, $short:expr, $meaning:literal $(,)?) => {
        go_bool_flag_impl!(
            $name,
            $alias,
            $short,
            concat!(
                $meaning,
                ". --",
                $name,
                "=<bool> is an frp-rs extension: Go registers no --",
                $name
            ),
            concat!($meaning, " (bare form = true)")
        )
    };
}

/// The one place the two branches are built; [`go_bool_flag`] and its two
/// siblings differ only in the help they pass.
///
/// The value branch is **long-only on purpose** — `$short` goes to the flag
/// branch and nowhere else. A short in an `.adjacent()` argument makes bpaf's
/// `ParseArgument` push the named argument onto `State::path` as soon as it
/// *attempts* a token, so that branch is reported one level deeper than the flag
/// branch and `this_or_that_picks_first` returns the deeper branch's error even
/// when the flag branch parsed the token successfully. Measured on `frps`:
/// with the short in both branches, `-vtrue`/`-vh`/`-vtok`/`-vp7000` — pflag
/// shorthand clusters that set `-v` and re-parse the rest, rc 0 on Go and rc 0
/// at the base head — all became rc 1. The short's `=` spelling (`-v=false`)
/// is instead expanded to the long form before bpaf sees argv; see
/// [`expand_bool_short_value_form`].
macro_rules! go_bool_flag_impl {
    ($name:literal, $alias:expr, $short:expr, $value_help:expr, $switch_help:expr $(,)?) => {{
        let value = go_bool_named($name, $alias, None, $value_help)
            .argument::<String>("BOOL")
            .adjacent()
            .parse(parse_go_bool);
        let switch = go_bool_named($name, $alias, $short, $switch_help).flag(true, false);
        construct!([value, switch])
    }};
}

/// Default of `--api-timeout`: Go frp v0.71.0's
/// `var adminAPITimeout = 30 * time.Second` (`cmd/frpc/sub/admin.go:32`).
pub const DEFAULT_ADMIN_API_TIMEOUT: Duration = Duration::from_secs(30);

/// Consume Go's `leadingInt` from `time.ParseDuration`: digits into a `u64`,
/// failing on the same overflow Go fails on.
fn leading_int(s: &[u8]) -> Result<(u64, usize), ()> {
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
fn leading_fraction(s: &[u8]) -> (u64, f64, usize) {
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
fn parse_go_duration(text: String) -> Result<Duration, String> {
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
fn api_timeout_parser() -> impl Parser<Duration> {
    long("api-timeout")
        .long("api_timeout")
        .argument::<String>("DURATION")
        .help("Timeout for admin API calls")
        .parse(parse_go_duration)
        .fallback(DEFAULT_ADMIN_API_TIMEOUT)
}

// ──────────────────────────────────────────────────────────────────────
// frps CLI — 30+ flags
// ──────────────────────────────────────────────────────────────────────

/// CLI arguments for frps (server).
///
/// Fields that can also appear in the config file use `Option<T>`: `Some`
/// means the user explicitly passed the flag on the CLI and it should
/// override the config value.  `None` means the config value is used.
#[derive(Debug, Clone)]
pub struct FrpsArgs {
    /// Config file path. `None` when `-c` was not given (default
    /// "frps.toml" is applied by [`FrpsArgs::config_path`]).
    /// Go frp v0.70.1 parity: when `-c` is given the file is authoritative
    /// and CLI config flags are ignored (audit task 9 finding 5).
    pub config: Option<String>,
    pub config_dir: Option<String>,
    pub bind_addr: Option<String>,
    pub bind_port: Option<u16>,
    pub token: Option<String>,
    pub allow_ports: Option<String>,
    pub allow_unsafe: Vec<String>,
    pub dashboard_addr: Option<String>,
    pub dashboard_port: Option<u16>,
    pub dashboard_user: Option<String>,
    pub dashboard_pwd: Option<String>,
    pub dashboard_tls_cert_file: Option<String>,
    pub dashboard_tls_key_file: Option<String>,
    pub dashboard_tls_mode: bool,
    pub enable_prometheus: bool,
    pub disable_log_color: bool,
    pub log_file: Option<String>,
    pub log_level: Option<String>,
    pub log_max_days: Option<i32>,
    pub log_format: Option<String>,
    pub kcp_bind_port: Option<u16>,
    pub quic_bind_port: Option<u16>,
    pub max_ports_per_client: Option<u64>,
    pub proxy_bind_addr: Option<String>,
    pub subdomain_host: Option<String>,
    pub tls_only: bool,
    pub vhost_http_port: Option<u16>,
    pub vhost_https_port: Option<u16>,
    /// VHost HTTP response-header timeout, in seconds. Go frp registers this as
    /// a **persistent root flag** with default 60
    /// (`cmd.PersistentFlags().Int64VarP(&c.VhostHTTPTimeout, "vhost_http_timeout", "", 60, …)`,
    /// `pkg/config/flags.go:237`), so `frps verify` inherits it too. `None`
    /// means the flag was absent and the config value stands;
    /// `ServerConfig::default()` already carries Go's 60
    /// (`frp-core/src/config/server.rs:249`), so the absent case is Go's default.
    /// The value is `i64`, matching `Int64VarP` and Go's `int64` config field:
    /// Go accepts `--vhost-http-timeout -1` (its floor then applies) and refuses
    /// only what does not fit an `int64` (measured on Go v0.71.0:
    /// `-9223372036854775808` rc 0, `9223372036854775807` rc 0,
    /// `9223372036854775808` rc 1 `value out of range`).
    ///
    /// **R6(b) (`TODO.md:10803`): "accept-and-ignore matches Go" is bounded.**
    /// The flag surface is Go's (the full `int64` accepted above), but the value
    /// that reaches the vhost handler is clamped: `<= 0` floors at 60 s and
    /// anything above 24 h is capped, where Go has no comparable cap. So the
    /// bound is "values `<= 0` or below the cap behave like Go"; a positive value
    /// above 24 h is accepted here and then silently shortened. Measured by the
    /// unit pin `frp-server/src/vhost/tests.rs:252` (`test_clamp_vhost_timeout`):
    /// `0 → 60`, `-1 → 60`, `86400 → 86400`, `86401 → 86400`, `i64::MAX →
    /// 86400`; the cap is `frp-server/src/vhost.rs:654`
    /// (`VHOST_TIMEOUT_CAP_SECS`).
    pub vhost_http_timeout: Option<i64>,
    pub strict_config: bool,
    pub show_version: bool,
}

/// CLI command for frps (server): the root command's run path, or one of its
/// child commands.
///
/// `frps` has a subcommand now, and Go has had one all along: `verify`
/// (`cmd/frps/verify.go:29`). Before this, `parse_frps_args` returned
/// [`FrpsArgs`] directly, which is the same shape as saying "`frps` has no
/// commands" — the premise the old `frp-core/src/cli.rs` comment recorded and
/// which was false.
///
/// The size gap between the two variants is accepted rather than boxed: one
/// value of this enum exists per process, built once from argv at startup
/// (`parse_frps_args`), so `Run`'s ~440 bytes are a single stack slot and `Box`
/// would buy nothing but an allocation plus a deref at every use.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum FrpsCmd {
    /// Normal mode: load the config (or the flags) and run the server.
    Run(FrpsArgs),
    /// Verify that a config file is valid, mirroring Go's `verifyCmd` and
    /// `frpc verify`. The `-c` value is **empty** when the flag was absent —
    /// Go's frps registers it with an empty default and `verifyCmd` answers
    /// that case with a message and rc 0 (`cmd/frps/verify.go:36-39`).
    Verify(VerifyArgs),
}

// Intermediate builder structs — each within bpaf construct! field limits.

struct SvrMeta {
    config: Option<String>,
    config_dir: Option<String>,
    strict_config: bool,
    show_version: bool,
}

struct SvrBind {
    bind_addr: Option<String>,
    bind_port: Option<u16>,
    proxy_bind_addr: Option<String>,
}

struct SvrAuth {
    token: Option<String>,
    allow_ports: Option<String>,
    allow_unsafe: Vec<String>,
}

struct SvrDashboard {
    dashboard_addr: Option<String>,
    dashboard_port: Option<u16>,
    dashboard_user: Option<String>,
    dashboard_pwd: Option<String>,
    dashboard_tls_cert_file: Option<String>,
    dashboard_tls_key_file: Option<String>,
    dashboard_tls_mode: bool,
    enable_prometheus: bool,
}

struct SvrLog {
    log_file: Option<String>,
    log_level: Option<String>,
    log_max_days: Option<i32>,
    log_format: Option<String>,
    disable_log_color: bool,
}

struct SvrTransport {
    kcp_bind_port: Option<u16>,
    quic_bind_port: Option<u16>,
    vhost_http_port: Option<u16>,
    vhost_https_port: Option<u16>,
    vhost_http_timeout: Option<i64>,
    subdomain_host: Option<String>,
    max_ports_per_client: Option<u64>,
    tls_only: bool,
}

// Composed builder: these 6 parsers feed into the final FrpsArgs.
struct FrpsBuild {
    meta: SvrMeta,
    bind: SvrBind,
    auth: SvrAuth,
    dash: SvrDashboard,
    log: SvrLog,
    transport: SvrTransport,
}

impl From<FrpsBuild> for FrpsArgs {
    fn from(b: FrpsBuild) -> Self {
        FrpsArgs {
            config: b.meta.config,
            config_dir: b.meta.config_dir,
            strict_config: b.meta.strict_config,
            show_version: b.meta.show_version,
            bind_addr: b.bind.bind_addr,
            bind_port: b.bind.bind_port,
            proxy_bind_addr: b.bind.proxy_bind_addr,
            token: b.auth.token,
            allow_ports: b.auth.allow_ports,
            allow_unsafe: b.auth.allow_unsafe,
            dashboard_addr: b.dash.dashboard_addr,
            dashboard_port: b.dash.dashboard_port,
            dashboard_user: b.dash.dashboard_user,
            dashboard_pwd: b.dash.dashboard_pwd,
            dashboard_tls_cert_file: b.dash.dashboard_tls_cert_file,
            dashboard_tls_key_file: b.dash.dashboard_tls_key_file,
            dashboard_tls_mode: b.dash.dashboard_tls_mode,
            enable_prometheus: b.dash.enable_prometheus,
            log_file: b.log.log_file,
            log_level: b.log.log_level,
            log_max_days: b.log.log_max_days,
            log_format: b.log.log_format,
            disable_log_color: b.log.disable_log_color,
            kcp_bind_port: b.transport.kcp_bind_port,
            quic_bind_port: b.transport.quic_bind_port,
            vhost_http_port: b.transport.vhost_http_port,
            vhost_https_port: b.transport.vhost_https_port,
            vhost_http_timeout: b.transport.vhost_http_timeout,
            subdomain_host: b.transport.subdomain_host,
            max_ports_per_client: b.transport.max_ports_per_client,
            tls_only: b.transport.tls_only,
        }
    }
}

// ─── Parser combinators ──────────────────────────────────────────────

/// The `-c`/`--config` parser of the frps **run** path.
///
/// No `.last()`: a repeated `-c` stays bpaf's "cannot be used multiple times in
/// this context" refusal, which is frp-rs's pre-existing, documented divergence
/// from Go's pflag last-wins (`docs/developing.md` § CLI inputs, row
/// `frps -c a.toml -c b.toml`). `frps verify` is a **new** surface and takes
/// [`config_arg`] instead, because Go's `verifyCmd` reads the same persistent
/// pflag and is last-wins like every `frpc` parser — measured, `frps verify -c
/// a.toml -c b.toml` loads `b.toml` (rc 0).
fn svr_config() -> impl Parser<Option<String>> {
    long("config")
        .short('c')
        .argument::<String>("FILE")
        .optional()
}

/// The frp-rs-only `--config-dir`/`--config_dir` extension, run path only.
///
/// Go's frps has no such flag (`unknown flag: --config-dir`, rc 1). It is
/// deliberately **not** part of the `verify` subcommand's surface — see
/// [`FrpsRootSlots`].
///
/// **R6(a) (`TODO.md:10803`): this lane does not read the loaded config's `[log]`
/// section.** `init_logging(&cli, None)` (`frps/src/main.rs:526`) runs before
/// `collect_config_files` (`frps/src/main.rs:542`), so the effective log level
/// comes from the flags alone. Measured over a config dir whose `frps.toml`
/// writes `[log] level = "warn"`: `frps --config-dir cfg` and
/// `frps --config-dir cfg --log-level ""` both log at `info` (11 `INFO` records,
/// 2491–2492 B) with the file's `warn` never consulted, and only an explicit
/// non-empty `--log-level warn` reaches 0 `INFO`. The empty value resolves to
/// `info` rather than `frp-core/src/logging.rs:108`'s `_debug_default`,
/// because that default is compiled in only under the opt-in `debug-logs`
/// feature. Recorded, not parity: Go has no `--config-dir` lane at all.
fn svr_config_dir() -> impl Parser<Option<String>> {
    long("config-dir")
        .long("config_dir")
        .argument::<String>("DIR")
        .optional()
}

/// The frp-rs-only `--log-format`/`--log_format` extension, run path only.
///
/// Go's frps has no such flag either, and its `frps --help` proves it rather
/// than a grep: diffing the two binaries' rendered flag sets gives
/// **frp-rs-only = {`config-dir`, `log-format`}** (measured on the head binary
/// and the Go v0.71.0 binary; the Go-only `vhost-http-timeout` this note used to
/// list is now registered — see `svr_transport`). So this is the second of
/// exactly two extension slots, and the
/// `verify` subcommand refuses it for the same reason it refuses the first:
/// measured, `frps verify --log-format json -c <valid>` is Go rc **1**
/// (`Error: unknown flag: --log-format` + usage, stderr, stdout 0 B) while
/// accepting it here printed `frps: … syntax is ok` and returned rc **0** — a
/// validation command reporting success for an argv Go rejects.
fn svr_log_format() -> impl Parser<Option<String>> {
    long("log-format")
        .long("log_format")
        .argument::<String>("FORMAT")
        .optional()
}

/// The three `frps` root slots whose parser differs between the run path and the
/// `verify` subcommand, passed as parsers so [`frps_build`] stays **one** builder
/// instead of two flag lists that can drift.
///
/// * `config` — the run path takes [`svr_config`], which has no `.last()`: a
///   repeated `-c` is bpaf's duplicate refusal, the pre-existing divergence from
///   pflag last-wins. `verify` takes [`config_arg`] (last-wins), because Go's
///   `verifyCmd` reads that same persistent `StringVar` — measured, `frps verify
///   -c a.toml -c b.toml` loads `b.toml` (rc 0) on both.
/// * `config_dir`, `log_format` — frp-rs-only **extensions** (the two the
///   `frps --help` diff above produces). The run path keeps both, as documented
///   extensions; `verify` passes `bpaf::pure(None)` for each, because accepting
///   either would make an argv Go answers `unknown flag: …` (rc 1) exit 0 from a
///   command whose only job is to say whether a config is valid.
///
/// The other `frps` root flags are **not** parameterized: they exist on both
/// sides and [`frps_build`] parses them once for both paths.
struct FrpsRootSlots<C, D, L> {
    config: C,
    config_dir: D,
    log_format: L,
}

/// The four root flags [`SvrMeta`] carries. The two config-selecting parsers are
/// parameters because the run path and the `verify` subcommand differ in those;
/// everything else is shared, so the two surfaces cannot drift.
fn svr_meta(
    config: impl Parser<Option<String>>,
    config_dir: impl Parser<Option<String>>,
) -> impl Parser<SvrMeta> {
    let strict_config = strict_config_parser();
    // Go: `-v, --version  version of frps` (`frps --help`), a pflag bool, so
    // `--version=false` starts the server there (measured, rc 124).
    let show_version = go_bool_flag!("version", None, Some('v'), "Version of frps");
    construct!(SvrMeta {
        config,
        config_dir,
        strict_config,
        show_version
    })
}

fn svr_bind() -> impl Parser<SvrBind> {
    let bind_addr = long("bind-addr")
        .long("bind_addr")
        .argument::<String>("IP")
        .optional();
    let bind_port = long("bind-port")
        .short('p')
        .long("bind_port")
        .argument::<u16>("PORT")
        .optional();
    let proxy_bind_addr = long("proxy-bind-addr")
        .long("proxy_bind_addr")
        .argument::<String>("IP")
        .optional();
    construct!(SvrBind {
        bind_addr,
        bind_port,
        proxy_bind_addr
    })
}

fn svr_auth() -> impl Parser<SvrAuth> {
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let allow_ports = long("allow-ports")
        .long("allow_ports")
        .argument::<String>("RANGES")
        .optional();
    let allow_unsafe = allow_unsafe_parser();
    construct!(SvrAuth {
        token,
        allow_ports,
        allow_unsafe
    })
}

fn svr_dashboard() -> impl Parser<SvrDashboard> {
    let dashboard_addr = long("dashboard-addr")
        .long("dashboard_addr")
        .argument::<String>("IP")
        .optional();
    let dashboard_port = long("dashboard-port")
        .long("dashboard_port")
        .argument::<u16>("PORT")
        .optional();
    let dashboard_user = long("dashboard-user")
        .long("dashboard_user")
        .argument::<String>("USER")
        .optional();
    let dashboard_pwd = long("dashboard-pwd")
        .long("dashboard_pwd")
        .argument::<String>("PWD")
        .optional();
    let dashboard_tls_cert_file = long("dashboard-tls-cert-file")
        .long("dashboard_tls_cert_file")
        .argument::<String>("FILE")
        .optional();
    let dashboard_tls_key_file = long("dashboard-tls-key-file")
        .long("dashboard_tls_key_file")
        .argument::<String>("FILE")
        .optional();
    // Go's `--dashboard-tls-mode` is a **string** flag, not a bool: it accepts
    // any value at parse time (`=auto`, `=bogus` and the empty string all start
    // frps, rc 124) and its bare form consumes the next token (`frps
    // --dashboard-tls-mode -c cfg` → `unknown command "cfg"`). frp-rs models
    // the field as a bool, so only Go's bool-shaped spellings can be honoured
    // here; the string residue is recorded in `docs/developing.md`.
    let dashboard_tls_mode = go_bool_flag_go_string!(
        "dashboard-tls-mode",
        Some("dashboard_tls_mode"),
        None,
        "Enable dashboard TLS mode",
    );
    let enable_prometheus = go_bool_flag!(
        "enable-prometheus",
        Some("enable_prometheus"),
        None,
        "Enable prometheus dashboard",
    );
    construct!(SvrDashboard {
        dashboard_addr,
        dashboard_port,
        dashboard_user,
        dashboard_pwd,
        dashboard_tls_cert_file,
        dashboard_tls_key_file,
        dashboard_tls_mode,
        enable_prometheus,
    })
}

/// The log half of the root surface. `log_format` arrives as a parameter because
/// it is the frp-rs-only extension [`FrpsRootSlots`] refuses on the `verify`
/// path; `log_file`, `log_level`, `log_max_days` and `disable_log_color` are Go
/// frps flags and are parsed once for both paths.
fn svr_log(log_format: impl Parser<Option<String>>) -> impl Parser<SvrLog> {
    let log_file = long("log-file")
        .long("log_file")
        .argument::<String>("FILE")
        .optional();
    let log_level = long("log-level")
        .long("log_level")
        .argument::<String>("LEVEL")
        .optional();
    let log_max_days = long("log-max-days")
        .long("log_max_days")
        .argument::<i32>("DAYS")
        .optional();
    let disable_log_color = go_bool_flag!(
        "disable-log-color",
        Some("disable_log_color"),
        None,
        "Disable log color in console",
    );
    construct!(SvrLog {
        log_file,
        log_level,
        log_max_days,
        log_format,
        disable_log_color
    })
}

fn svr_transport() -> impl Parser<SvrTransport> {
    #[cfg(feature = "kcp")]
    let kcp_bind_port = long("kcp-bind-port")
        .long("kcp_bind_port")
        .argument::<u16>("PORT")
        .optional();
    #[cfg(not(feature = "kcp"))]
    let kcp_bind_port = bpaf::pure(None);
    #[cfg(feature = "quic")]
    let quic_bind_port = long("quic-bind-port")
        .long("quic_bind_port")
        .argument::<u16>("PORT")
        .optional();
    #[cfg(not(feature = "quic"))]
    let quic_bind_port = bpaf::pure(None);
    let vhost_http_port = long("vhost-http-port")
        .long("vhost_http_port")
        .argument::<u16>("PORT")
        .optional();
    let vhost_https_port = long("vhost-https-port")
        .long("vhost_https_port")
        .argument::<u16>("PORT")
        .optional();
    // Go registers the name with underscores and turns every `_` into `-` via
    // `WordSepNormalizeFunc` (`pkg/config/flags.go:31-36`), so both spellings
    // are accepted and `--help` renders the hyphen form. Same pairing as the
    // two `vhost-http(s)-port` flags above; measured on Go v0.71.0:
    // `frps verify --vhost-http-timeout 30 -c <valid>` and
    // `frps verify --vhost_http_timeout 30 -c <valid>` are both rc 0.
    // Signed, because Go's is `Int64VarP`/`int64`: `-1` is accepted there and
    // the out-of-range boundary is the `int64` one, not `u64`'s.
    let vhost_http_timeout = long("vhost-http-timeout")
        .long("vhost_http_timeout")
        .argument::<i64>("SECONDS")
        .optional();
    let subdomain_host = long("subdomain-host")
        .long("subdomain_host")
        .argument::<String>("HOST")
        .optional();
    let max_ports_per_client = long("max-ports-per-client")
        .long("max_ports_per_client")
        .argument::<u64>("N")
        .optional();
    let tls_only = go_bool_flag!("tls-only", Some("tls_only"), None, "Frps TLS only");
    construct!(SvrTransport {
        kcp_bind_port,
        quic_bind_port,
        vhost_http_port,
        vhost_https_port,
        vhost_http_timeout,
        subdomain_host,
        max_ports_per_client,
        tls_only,
    })
}

fn frps_build(
    slots: FrpsRootSlots<
        impl Parser<Option<String>>,
        impl Parser<Option<String>>,
        impl Parser<Option<String>>,
    >,
) -> impl Parser<FrpsBuild> {
    let meta = svr_meta(slots.config, slots.config_dir);
    let bind = svr_bind();
    let auth = svr_auth();
    let dash = svr_dashboard();
    let log = svr_log(slots.log_format);
    let transport = svr_transport();
    construct!(FrpsBuild {
        meta,
        bind,
        auth,
        dash,
        log,
        transport
    })
}

/// Raw parser for the frps **run** path — the root command's own arguments,
/// which is what the binary runs when no child command is selected. Returns the
/// parser, doesn't run it; for the whole `frps` surface (run + `verify`) use
/// [`frps_parser`].
pub fn frps_args() -> impl Parser<FrpsArgs> {
    frps_build(FrpsRootSlots {
        config: svr_config(),
        config_dir: svr_config_dir(),
        log_format: svr_log_format(),
    })
    .map(FrpsArgs::from)
}

/// The whole `frps` surface: the `verify` child command, then the root
/// command's run path — the same branch order [`frpc_parser`] uses.
///
/// Command branches come first for the same reason as on `frpc`: bpaf picks a
/// branch *before* dispatch, and a command branch matches the command token
/// where it sits, so the run branch must not get first refusal on an argv whose
/// first token is a command name. `verify` leads the argv only after
/// [`hoist_leading_subcommand`] moved it there; that is what makes
/// `frps -c cfg.toml verify` reach `verify_cmd` instead of the run branch's
/// leftover-token refusal (measured on Go: rc 0).
fn frps_parser() -> impl Parser<FrpsCmd> {
    let run = frps_args().map(FrpsCmd::Run);
    construct!([frps_verify_cmd(), run])
}

/// The `frps verify` subcommand, mirroring Go's `verifyCmd`
/// (`cmd/frps/verify.go`, registered on `rootCmd` at `:29`).
///
/// Go's `verifyCmd` reads exactly two persistent root flags itself — `cfgFile`
/// and `strictConfigMode` (`cmd/frps/verify.go:36,40`) — and **accepts and
/// ignores** every other flag Go's `frps` root registers, because they hang off
/// `rootCmd`: `config.RegisterServerConfigFlags(rootCmd, &serverCfg)`
/// (`cmd/frps/root.go:50`) plus `--version` and `--allow-unsafe` (`:44-48`).
/// One of those "ignored" flags is not really ignored on either side:
/// `--allow-unsafe` is consulted by the post-load unsafe-feature gate that Go
/// runs from `ValidateServerConfig` (measured on v0.71.0: `frps verify -c <exec
/// tokenSource cfg>` is rc 1 without it, rc 0 with it), so frp-rs reads it here
/// too and hands it to `run_verify` — see [`VerifyArgs::allow_unsafe`]. Measured
/// on Go v0.71.0:
/// `frps verify --help` prints the whole surface under `Global Flags`, and
/// `frps verify --bind-port <free> -c <valid>`,
/// `frps verify --allow-unsafe X -c <valid>` and
/// `frps verify --version -c <valid>` are all rc 0 with the *verify* output (no
/// version line). Parsing through [`frps_build`] and keeping only the three fields
/// reproduces that acceptance without a second hand-written flag list — for
/// **every root flag frp-rs models**, which is the precise claim. The one such
/// flag that used to be missing was Go's `--vhost-http-timeout`, so `frps
/// verify --vhost-http-timeout 30 -c <valid>` was rc **1** here and rc **0** on
/// Go, identically on the run path; it is now registered on `SvrTransport` in
/// `svr_transport()` and accepted on both paths (measured here: both spellings
/// rc 0 on `verify`, both start a listener on the run path), so `verify` inherits
/// it through the one shared builder. It stays unread by `verifyCmd` in Go too —
/// the value is applied only on the flags-only lane
/// ([`FrpsArgs::cli_overrides_enabled`]).
///
/// The three slots where this differs from the run path are the
/// [`FrpsRootSlots`] fields: `-c` is [`config_arg`] (pflag last-wins; Go's
/// verifyCmd reads the same persistent flag, so `-c a -c b` loads `b` —
/// measured rc 0 on `b`), and the two frp-rs-only extensions `--config-dir` and
/// `--log-format` are refused (`bpaf::pure(None)`), because Go has neither flag
/// and refusing them keeps Go's rc 1 (`unknown flag: …`) instead of silently
/// succeeding on flags this command would never read. The log-format slot is the
/// one this round closed: it used to ride in through `frps_build` and made
/// `frps verify --log-format json -c <valid>` print `syntax is ok` and exit **0**
/// where Go exits **1**.
///
/// `config` is therefore `Option<String>` and **empty** when absent: Go
/// registers `-c` with an empty default on frps (`cmd/frps/root.go:44`) and
/// `verifyCmd` answers an empty path with `frps: the configuration file is not
/// specified` + rc **0** (`cmd/frps/verify.go:36-39`; measured), unlike `frpc`,
/// whose default is `./frpc.ini`. `frps/src/main.rs`'s `run_verify` reproduces
/// that branch.
fn frps_verify_cmd() -> impl Parser<FrpsCmd> {
    let args = frps_build(FrpsRootSlots {
        config: config_arg().optional(),
        config_dir: bpaf::pure(None),
        log_format: bpaf::pure(None),
    })
    .map(|b| VerifyArgs {
        config: b.meta.config.unwrap_or_default(),
        strict_config: b.meta.strict_config,
        allow_unsafe: b.auth.allow_unsafe,
    });
    args.to_options()
        .command("verify")
        .help("Verify that the configuration is valid")
        .map(FrpsCmd::Verify)
}

/// The output width bpaf's own `OptionParser::run` passes to
/// `ParseFailure::print_message` — `OptionParserInfo::default().max_width`
/// (`bpaf-0.9.27/src/info.rs:46`), and no parser here calls `.max_width()`.
/// Spelled out because the two entry points below build bpaf's `Args` by hand
/// (to apply [`expand_bool_short_value_form`]) and therefore cannot use `run()`.
const CLI_OUTPUT_WIDTH: usize = 100;

/// Expand pflag's `-<bool short>=<value>` spelling into the long spelling,
/// before bpaf sees argv.
///
/// Go's pflag treats `-v=false` as the same variable as `--version=false`
/// (measured on Go frp v0.71.0: `frps -v=false -c <valid config>` starts the
/// server, rc 124), while `-vfalse` — no `=` — is a *shorthand cluster*, not a
/// value: pflag sets `-v` and re-parses `-t rue`, so that one must keep reaching
/// bpaf's short-flag parser untouched. bpaf cannot express both in one
/// alternation (see [`go_bool_flag_impl`]), so the `=` form is rewritten here
/// and the cluster form is left alone.
///
/// Only `-v` is rewritten because it is the only bool **short** either binary
/// registers; every other short (`-c`, `-t`, `-p`, `-L`, …) takes a value and
/// already parses its `=` spelling through bpaf.
///
/// `argv` is the process argv **without** `argv[0]`, matching what bpaf's
/// `Args::current_args` hands the parser.
fn expand_bool_short_value_form(argv: Vec<OsString>) -> Vec<OsString> {
    // Nothing after the first `--` is a flag, so nothing there is a shorthand
    // either. Rewriting past it would put a token the user never typed into a
    // rejection message: `frps -- -v=false` would answer
    // `` `--version=false` is not expected `` where the base head and Go both
    // name `-v=false`.
    let mut seen_separator = false;
    argv.into_iter()
        .map(|arg| {
            if seen_separator {
                return arg;
            }
            if arg == "--" {
                seen_separator = true;
                return arg;
            }
            match arg.to_str().and_then(|text| text.strip_prefix("-v=")) {
                Some(value) => OsString::from(format!("--version={value}")),
                None => arg,
            }
        })
        .collect()
}

/// The short flags that take a value, split by the **context** pflag parses them
/// in, because the set is not one list and the directions are easy to invert:
///
/// * `-c` is a value-taking short on every parser of both binaries
///   (`frp-core/src/cli.rs`, `config_arg`);
/// * `-p` and `-t` are `frps`'s own on its **root** — `bind_port`
///   (`pkg/config/flags.go:231`) and `token` (`:247`) — and `-t` is also
///   `frpc`'s `token` on its proxy and visitor subcommands (`:171`);
/// * `-L` is **frpc's run path only** — frp-rs's alias for `--log-level`
///   (`frp-core/src/cli.rs`, the `run_mode` parser). It is *not* a Go shorthand
///   at all: Go registers `log_level` with an empty shorthand
///   (`pkg/config/flags.go:161`), so Go answers `unknown shorthand flag: 'L' in
///   -L`. It is therefore in the **root** set (the run path is the root's) and
///   absent from the subcommand set, which is why `frpc -hL` is reported (frp-rs
///   does have the short) and `frpc status -hL` / `frps verify -hL` /
///   `frpc tcp -hL` are **not** (frp-rs does not, so no fabricated
///   `flag needs an argument: 'L'` line — Go says `unknown shorthand flag` and
///   the base prints help, and both are closer to Go than an invented line).
///
/// [`value_taking_short_name`] is the membership test; the walk, the attachment
/// and the `--help=<bool>` expansion all read it through
/// [`claims_the_next_token`]. `-v` is deliberately absent — Go registers it as a
/// pflag **bool**, so it never needs an argument.
///
/// `frpc`'s root, which is the run path: `-c` (frp-rs's `config_arg`) and `-L`
/// (frp-rs's own alias for `--log-level`, `frp-core/src/cli.rs` `run_mode`) are
/// registered there; **`-p` and `-t` are not** — frp-rs's `frpc` root has no
/// `bind_port`/`token`, and neither does Go's (`log_level` itself is registered
/// with an empty shorthand, `pkg/config/flags.go:161`, so Go's `-L` refusal is
/// `unknown shorthand flag: 'L' in -L`). Keeping `p` and `t` in this set is a
/// deliberate choice about which error a two-character `-x` gets rather than a
/// claim about registration: pflag classifies any 2-char single-dash token as a
/// short that eats the next token, so `frpc -t -h` is Go's `unknown shorthand
/// flag: 't' in -t` with **rc 1 on stderr** — and the set is what makes this tree
/// report pflag's missing-argument line with the same rc and stream instead of
/// letting bpaf print help with rc 0. Dropping them would regress those rows
/// toward the base.
const VALUE_TAKING_SHORTS_FRPC_ROOT: [char; 4] = ['c', 'p', 't', 'L'];

/// `frps`'s root takes `-c`, `-p` (`bind_port`, `pkg/config/flags.go:231`) and
/// `-t` (`token`, `:247`) and **no `-L`**: Go registers `log_level` with an empty
/// shorthand (`:244`) and frp-rs's `svr_log` gives `log-level` no short either.
/// The two roots therefore need **separate** sets — sharing frpc's made
/// `frps -hL` print a `flag needs an argument: 'L' in -L` for a short frps does
/// not register, which is exactly the fabricated line this constant exists to
/// avoid on the subcommand set.
const VALUE_TAKING_SHORTS_FRPS_ROOT: [char; 3] = ['c', 'p', 't'];

/// Every **subcommand** of both binaries: `-c` is persistent on both, and `-p` /
/// `-t` cover the `frps verify` and `frpc` proxy surfaces. `-L` is absent here on
/// both binaries, so `frpc status -hL`, `frpc tcp -hL` and `frps verify -hL` get
/// bpaf's own reading rather than a missing-argument line for a short those
/// parsers do not have.
const VALUE_TAKING_SHORTS_SUBCOMMAND: [char; 3] = ['c', 'p', 't'];

/// The root set for a binary: the two roots are **not** the same list.
fn value_taking_root_shorts(root: RootCommand) -> &'static [char] {
    match root {
        RootCommand::Frpc => &VALUE_TAKING_SHORTS_FRPC_ROOT,
        RootCommand::Frps => &VALUE_TAKING_SHORTS_FRPS_ROOT,
    }
}

/// Which value-taking short set a pass uses: the root command's (a bare `frpc`
/// invocation, which is the run path and *does* have `-L`, or `frps`'s root) or a
/// subcommand's (which does not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShortFlagContext {
    value_taking: &'static [char],
}

impl ShortFlagContext {
    /// The context for an argv whose command word may not lead yet — the attach
    /// pass runs **before** the hoist, so it reads the first **bare word**.
    fn of_first_bare_word(argv: &[OsString], root: RootCommand) -> Self {
        let on_subcommand = argv
            .iter()
            .find(|token| !token.to_string_lossy().starts_with('-'))
            .and_then(|token| token.to_str())
            .is_some_and(|word| is_known_subcommand(word, root));
        Self {
            value_taking: if on_subcommand {
                &VALUE_TAKING_SHORTS_SUBCOMMAND
            } else {
                value_taking_root_shorts(root)
            },
        }
    }

    /// `argv` is the **hoisted** argv, so a leading command word means the
    /// parse happens on that subcommand's flag set — which is the only reason
    /// `-L` is in one context and not the other.
    fn of(argv: &[OsString], root: RootCommand) -> Self {
        let on_subcommand = argv
            .first()
            .and_then(|token| token.to_str())
            .is_some_and(|word| is_known_subcommand(word, root));
        Self {
            value_taking: if on_subcommand {
                &VALUE_TAKING_SHORTS_SUBCOMMAND
            } else {
                value_taking_root_shorts(root)
            },
        }
    }
}

/// The value-taking short a token **names** and does not already carry a value
/// for, or `None`.
///
/// `-c`, `-p`, `-t`, `-L` in the right context are that shape; `-hc`, `-hcx` and
/// `-h` are not (a value-taking short is not their first character, or
/// something follows it inside the cluster and pflag would hand that to the
/// flag as its value); `-c=x` and `-cx` are not either, for the same reason —
/// and a long `--config` is excluded by the single-dash test.
fn value_taking_short_name(token: &OsStr, context: ShortFlagContext) -> Option<char> {
    let text = token.to_str()?;
    let cluster = text.strip_prefix('-')?;
    if cluster.contains('=') {
        return None;
    }
    let mut chars = cluster.chars();
    let named = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    context.value_taking.contains(&named).then_some(named)
}

/// A single-dash cluster whose **first** short is pflag's help short `h` and
/// whose remainder is exactly one value-taking short of this context — `-hc`,
/// `-hL`. `-h` alone, `-hcx` (pflag hands `x` to `-c` as its value) and `-hc=x`
/// are not this shape.
///
/// A cluster is different from a bare `-c` in one way that matters here: pflag
/// never reports a *missing argument* for it in this build. `-c` with nothing
/// after it is bpaf's own error (rc 1, stderr), so the walk does not need to
/// improve it; `-hc` reaches bpaf's **help** instead, which is the defect.
fn help_cluster_naming_a_value_short(token: &OsStr, context: ShortFlagContext) -> Option<char> {
    let text = token.to_str()?;
    let cluster = text.strip_prefix('-')?;
    if cluster.len() < 2 || cluster.starts_with('-') || cluster.contains('=') {
        return None;
    }
    let mut chars = cluster.chars();
    if chars.next() != Some('h') {
        return None;
    }
    let needed = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    context.value_taking.contains(&needed).then_some(needed)
}

/// Attach a flag-shaped value to the flag that owns it, the way pflag's
/// `parseShortArg` / `parseLongArg` hand the next token over without ever asking
/// what it looks like.
///
/// This is the same repair [`rewrite_config_dash_values`] makes for the
/// config-selecting flags, generalised to **every** value-taking token of the
/// active context, and it exists because bpaf cannot see a value once the token
/// starts with `-`: it classifies the token first, so `frps -c CFG -t -h` reaches
/// bpaf as `-t` with no value and `-h` as the help trigger, and the server exits
/// 0 with root help where Go takes `-h` as `--token`'s value, loads the config
/// and exits **1** (measured: Go `open CFG: …`, 36 B on stdout; the base head
/// printed 3571 B of help with rc 0). `-t=-h` is the same flag and the same
/// value to pflag, and bpaf parses it.
///
/// The value attached may be **anything**, `-h` included:
/// `frps -c CFG -t -h` is `--token` taking `-h`, which is why the server loads
/// the config and exits 1 as Go does. What is *not* attached is a flag that is
/// not a value-taking **argument** in frp-rs — see
/// [`claims_the_next_token`] and [`VALUE_TAKING_LONG_FLAGS`] — because the
/// `go_bool_flag!` family parses its value only in the `.adjacent()` spelling
/// and an unknown name has no value at all.
///
/// Runs after [`rewrite_config_dash_values`]; a token that already contains `=`
/// (either pass's output) is copied through, never re-attached: doing so once
/// turned `frpc verify --config-dir --help=false -c CFG` into
/// `--config-dir=--help=false=-c`, rc 1 where the base and Go are rc 0.
fn attach_flag_shaped_values(argv: Vec<OsString>, root: RootCommand) -> Vec<OsString> {
    // The command word may still be anywhere in this argv (the hoist runs
    // after), so the context comes from the first **bare word** rather than the
    // first token — `frps -c CFG verify` is a subcommand parse even though it
    // does not lead.
    let context = ShortFlagContext::of_first_bare_word(&argv, root);
    let mut out = Vec::with_capacity(argv.len());
    let mut seen_separator = false;
    let mut index = 0;
    while index < argv.len() {
        let arg = &argv[index];
        if seen_separator {
            out.push(arg.clone());
            index += 1;
            continue;
        }
        if arg == "--" {
            seen_separator = true;
            out.push(arg.clone());
            index += 1;
            continue;
        }
        // Exactly the flags the parser hands the next token to
        // ([`claims_the_next_token`]), which is the same question [`walk_argv`]
        // and the `--help=<bool>` expansion ask, so the three passes cannot
        // disagree about who owns a token. A **cluster** is excluded: the walk
        // already gives it the next token and bpaf reads `-hc -h` as help, which
        // is what Go and the base do.
        //
        // It is deliberately *not* `consumes_value`, which answers cobra's
        // question about the **root** command's pflag set: that says "takes a
        // value" for `--dashboard_tls_mode` (registered with
        // `VarP(BoolFuncFlag{…})`, no `NoOptDefVal`) and for names frp-rs does
        // not know at all, so attaching turned `frps verify --dashboard_tls_mode
        // -c CFG` into a refused bool value (Go and the base: rc 0, 114 B) and
        // `frpc tcp --disable-log-color -h` into an error where Go and the base
        // print help with rc 0.
        let takes_value = claims_the_next_token(arg, context, root)
            && help_cluster_naming_a_value_short(arg, context).is_none();
        // A flag-shaped next token is this flag's value whatever it contains —
        // `--help=false`, `-h`, `-c=CFG` and `-v` alike. pflag hands the next
        // token over without inspecting it, and bpaf will only accept a
        // `-`-prefixed value when it is attached, so the `=` inside the *value*
        // must not disqualify it: `frps verify --token --help=false -c CFG` is
        // the row that showed this.
        let next_is_attachable = argv.get(index + 1).is_some_and(|next| {
            let text = next.to_string_lossy();
            text.starts_with('-') && next != "-"
        });
        if takes_value && !arg.to_string_lossy().contains('=') && next_is_attachable {
            let mut joined = arg.clone();
            joined.push("=");
            joined.push(&argv[index + 1]);
            out.push(joined);
            index += 2;
            continue;
        }
        out.push(arg.clone());
        index += 1;
    }
    out
}

/// The **long** flags frp-rs's own parsers take a value for, collected from this
/// file (`long("…")` … `.argument::<T>(…)`); both spellings of every name are
/// listed because frp-rs registers the hyphen and underscore forms as one flag.
///
/// Read by [`claims_the_next_token`], which the walk, the attachment and the
/// `--help=<bool>` expansion all share. It exists because bpaf's metadata is not
/// public (`bpaf::Meta::Item` holds a private `Item`), so "does this flag take a
/// value?" cannot be asked of the parser at runtime, and because the two obvious
/// proxies are both wrong for that question:
///
/// * `consumes_value` answers cobra's `stripFlags` question — "what does the
///   *root* command's pflag set do with this token" — which is right for command
///   resolution and wrong here: it says yes for every flag Go registers as a
///   `VarP(BoolFuncFlag{…})` (no `NoOptDefVal`) and for every unknown name. Using
///   it made `frps verify --dashboard_tls_mode -c CFG` become
///   `--dashboard_tls_mode=-c` and the **bool** parser refuse the value (Go and
///   the base: rc 0 with 114 B on stdout; that head: rc 1), and turned
///   `frpc tcp --disable-log-color -h` into an error where Go and the base print
///   help with rc 0.
/// * "not a bool" is not decidable either: a flag can be a bool on one command
///   and an argument on another.
///
/// The bools are deliberately absent (`--dashboard-tls-mode`, `--disable-log-color`,
/// `--enable-prometheus`, `--tls-only`, `--json`, `--strict-config`, `--version`,
/// `--uc`, `--ue` — and frp-rs's older `--use-compression`/`--use-encryption`
/// aliases of those two): frp-rs parses each of them with the
/// `go_bool_flag!` family, whose value branch is `.adjacent()`, so a separate
/// token is never their value and attaching one makes the bool parser refuse it.
///
/// **Scope, stated rather than implied:** this is a curated list, derived
/// mechanically from this file's `long("…") … .argument` chains (both spellings
/// in the chain are taken, whatever order the `.long()`/`.short()`/`.help()`
/// calls come in — `svr_bind` is `long("bind-port").short('p').long("bind_port")`,
/// so both spellings come from one chain and a matcher that expected the shorts
/// last missed **both**). A name **frp-rs does not register** is deliberately
/// absent even when Go accepts it, because attaching a value to an unknown name
/// is exactly the round-3 regression: the absence is the safe side, and the cost
/// is only that pflag's `--flag value` spelling stays refused where Go (whose
/// `config.WordSepNormalizeFunc` folds `_` to `-`) would take it. A value-taking
/// long flag added later that is missing here is simply not attached, which
/// leaves bpaf's own refusal in place — a divergence from pflag, not a fabricated
/// error. The unit test below pins the members the measured rows use and every
/// excluded bool, in both directions.
const VALUE_TAKING_LONG_FLAGS: &[&str] = &[
    "admin-addr",
    "admin-port",
    "admin-pwd",
    "admin-user",
    "admin_addr",
    "admin_port",
    "admin_pwd",
    "admin_user",
    "allow-ports",
    "allow-unsafe",
    "allow_ports",
    "allow_unsafe",
    "api-timeout",
    "api_timeout",
    "bind-addr",
    "bind-port",
    "bind_addr",
    "bind_port",
    "config",
    "config-dir",
    "config_dir",
    "custom-domain",
    "custom-domains",
    "custom_domain",
    "custom_domains",
    "dashboard-addr",
    "dashboard-port",
    "dashboard-pwd",
    "dashboard-tls-cert-file",
    "dashboard-tls-key-file",
    "dashboard-user",
    "dashboard_addr",
    "dashboard_port",
    "dashboard_pwd",
    "dashboard_tls_cert_file",
    "dashboard_tls_key_file",
    "dashboard_user",
    "host-header-rewrite",
    "host_header_rewrite",
    "http-pwd",
    "http-user",
    "http_pwd",
    "http_user",
    "kcp-bind-port",
    "kcp_bind_port",
    "local-ip",
    "local-port",
    "local_ip",
    "local_port",
    "locations",
    "log-file",
    "log-format",
    "log-level",
    "log-max-days",
    "log_file",
    "log_format",
    "log_level",
    "log_max_days",
    "max-ports-per-client",
    "max_ports_per_client",
    "mux",
    "mux-port",
    "mux_port",
    "proxy-bind-addr",
    "proxy-name",
    "proxy_bind_addr",
    "proxy_name",
    "quic-bind-port",
    "quic_bind_port",
    "remote-port",
    "remote_port",
    "sd",
    "server-addr",
    "server-name",
    "server-port",
    "server_addr",
    "server_name",
    "server_port",
    "sk",
    "subdomain",
    "subdomain-host",
    "subdomain_host",
    "tls-server-name",
    "token",
    "vhost-http-port",
    "vhost-http-timeout",
    "vhost-https-port",
    "vhost_http_port",
    "vhost_http_timeout",
    "vhost_https_port",
];

/// Whether pflag / bpaf would hand the token **after** this one to it as a value,
/// for the three passes that have to agree about token ownership.
///
/// * the two **bare help spellings** never claim: pflag's `-h` is a bool and
///   bpaf's is built in, so `frpc -h -c` leaves `-c` to be the value-taking short
///   that fails, and `frpc -c -h` is `-c` taking `-h`. (Measured: Go is rc 1 with
///   `flag needs an argument: 'c' in -c` on stderr, 637 B, for the first and
///   `open -h: no such file or directory` on stdout for the second.)
/// * an `-h<value-short>` **cluster** claims ([`help_cluster_naming_a_value_short`]),
///   which is the shape the refusal pass reports;
/// * a **long** flag claims only when [`VALUE_TAKING_LONG_FLAGS`] has it;
/// * a **short** flag claims on `consumes_value`'s short rule (a single `-x` that
///   is not `-v`), so an unknown short such as `-z` still claims and its error
///   comes from the parser rather than from a help print.
fn claims_the_next_token(token: &OsStr, context: ShortFlagContext, root: RootCommand) -> bool {
    if matches!(token.to_str(), Some("-h") | Some("--help")) {
        return false;
    }
    if let Some(text) = token.to_str() {
        if let Some(long) = text.strip_prefix("--") {
            // `--flag=value` already carries its value, so it claims nothing —
            // `rewrite_config_dash_values` and this pass both produce that
            // spelling, and re-attaching it made
            // `frpc verify --config-dir --help=false -c CFG` into
            // `--config-dir=--help=false=-c` (base and Go: rc 0).
            if long.contains('=') {
                return false;
            }
            return VALUE_TAKING_LONG_FLAGS.contains(&long);
        }
    }
    help_cluster_naming_a_value_short(token, context).is_some() || consumes_value(token, root)
}

/// The result of walking the **hoisted** argv the way pflag's `parseShortArg` /
/// `parseLongArg` walk it.
struct ArgvWalk {
    /// Indices pflag hands to a flag as its **value**, so no later pass may read
    /// them as flags: `frpc -hc --help=false status` is `-c`'s value, not a help
    /// request, and `frpc -hc -hc` gives the second cluster to the first's `-c`.
    consumed: Vec<bool>,
    /// `Some(c)` when the walk ended needing a value for short `c` — the one
    /// shape that reaches a parse error.
    needs_argument: Option<char>,
    /// Whether the token that produced [`Self::needs_argument`] was a `-h<short>`
    /// **cluster** (as opposed to a bare `-c`). Only the cluster shape is this
    /// pass's business: a bare `-c` with nothing after it is already a bpaf
    /// error on the right stream with rc 1 (`` `-c` requires an argument `FILE` ``,
    /// measured 40 B on stderr), while `-hc` reaches bpaf's help and exits 0.
    needs_argument_is_help_cluster: bool,
}

/// Walk `argv` left to right, giving every value-taking token the token that
/// follows it, and report where that leaves the parse.
///
/// `--` ends the walk: everything after it is a positional to pflag and never a
/// flag. The value-taking tokens are **context-dependent**
/// ([`ShortFlagContext`]), which is what keeps the walk from inventing values
/// for shorts Go does not have: on `frpc`'s root, `-t` and `-L` are not
/// value-taking, so `frpc -t -h` leaves the bare `-h` for bpaf (Go: `unknown
/// shorthand flag: 't' in -t`, rc 1 — a message, not a missing value), while
/// `frps -p -h` does pair them (`p` is Go's `-p`), and Go answers
/// `invalid argument "-h" for "-p, --bind-port"` — rc 1 and stderr are the parts
/// the walk reproduces.
///
/// A token is only processed when nothing before it claimed it: `frpc -hc -hc`
/// is one cluster whose `c` takes the next token, not two clusters, and reading
/// the second one again is what made the first version of this walk report an
/// argument error for argv Go answers with help.
///
/// `consumed[i]` is also how [`expand_help_bool_value_form`] knows that a
/// `--help=<bool>` token is *a value* rather than a flag, which is the fix for
/// `frpc -hc --help=false status` and `frpc --config --help=false status`.
fn walk_argv(argv: &[OsString], context: ShortFlagContext, root: RootCommand) -> ArgvWalk {
    let mut consumed = vec![false; argv.len()];
    // The index of a value-taking token that claimed the **next** token but did
    // not get one, and whether that token was an `-h<short>` cluster.
    let mut dangling: Option<(usize, char, bool)> = None;
    let mut index = 0;
    while index < argv.len() {
        let token = &argv[index];
        if token == "--" {
            break;
        }
        if consumed[index] {
            // Another flag's value. It satisfies that flag; it is not itself
            // parsed, so it can neither claim the next token nor be reported.
            index += 1;
            continue;
        }
        let cluster = help_cluster_naming_a_value_short(token, context);
        if !claims_the_next_token(token, context, root) {
            index += 1;
            continue;
        }
        // Only a **bare value-taking short** or the cluster can be reported; a
        // long flag or a short this context does not call value-taking still
        // claims its token, it just leaves the refusal to bpaf.
        let reportable = value_taking_short_name(token, context)
            .map(|named| (named, false))
            .or_else(|| cluster.map(|named| (named, true)));
        if index + 1 < argv.len() {
            // Whatever follows is this flag's value, flag-shaped or not, and the
            // walk steps past it so it is never read as a flag of its own —
            // `frpc -hc -v` and `frpc -hc -hc` are both one flag plus a value.
            consumed[index + 1] = true;
            dangling = None;
        } else {
            // The last token needs a value, and R2's F2 is that a **bare** one
            // counts when a bare help flag immediately precedes it: `frpc -h -c`,
            // `frpc --help -t`, `frpc -h -c status` and `frpc status -h -c` are
            // Go rc 1 with `flag needs an argument: 'c' in -c` on stderr (637 B
            // for the status rows, 1351 B for the root ones), where bpaf prints
            // help and exits 0. The cluster shape counts on its own, because
            // `-hc` reaches help with nothing to take.
            let preceded_by_help =
                index > 0 && matches!(argv[index - 1].to_str(), Some("-h") | Some("--help"));
            dangling = reportable
                .map(|(named, is_cluster)| (index, named, is_cluster || preceded_by_help));
        }
        // Both shapes took the next token, so the walk steps past it.
        index += 2;
    }
    ArgvWalk {
        consumed,
        needs_argument: dangling.map(|(_, named, _)| named),
        needs_argument_is_help_cluster: dangling.is_some_and(|(_, _, cluster)| cluster),
    }
}

/// Refuse a pflag shorthand cluster that was left without its value, the way
/// pflag/cobra do — see [`walk_argv`] for the rule and its scope.
///
/// Only the **cluster** shape is reported (`frpc -hc`, `frpc -hc status`,
/// `frpc -hL`): a bare dangling `-c` is already a bpaf error with rc 1 on the
/// right stream, and rewriting it would move a row that already agrees on rc,
/// stream and the fact that it failed.
///
/// The line is pflag's (`pflag-1.0.5/flag.go:1058`). Go's stderr for
/// `frpc -hc status` is 637 B — that line plus cobra's usage block; frp-rs's
/// parse failures print no usage block anywhere (measured: `frpc -c` is 40 B on
/// stderr), so the line is 41 B here. rc 1 and the **stderr** stream are the
/// matched parts; the trailing usage block is the help-shape divergence
/// recorded in `docs/developing.md` § `--help=<bool>`, not claimed as parity.
///
/// Exits the process directly rather than returning a `bpaf::ParseFailure`,
/// because bpaf's own `-h` short-circuits to help for exactly this argv (that is
/// the bug), so there is no parser state to hand the failure to.
fn reject_pflag_shorthand_cluster_that_needs_a_value(argv: &[OsString], root: RootCommand) {
    if argv.iter().any(|token| token == "--") {
        return;
    }
    let walk = walk_argv(argv, ShortFlagContext::of(argv, root), root);
    let Some(needed) = walk.needs_argument else {
        return;
    };
    if !walk.needs_argument_is_help_cluster {
        return;
    }
    eprintln!("Error: flag needs an argument: '{needed}' in -{needed}");
    std::process::exit(1);
}

/// The frp-rs spelling of Go's attached pflag bool `--help=<bool>`, applied to
/// argv **before** bpaf runs.
///
/// Go registers `--help`/`-h` with pflag's bool machinery, so `--help=false`
/// *sets the flag to false* and cobra's `execute` only acts on it when it is
/// true (`cobra-1.8.0/command.go:892-894`, `if helpVal { return flag.ErrHelp }`).
/// A pflag bool never consumes a following token, so the subcommand still
/// resolves and **runs**: measured on Go v0.71.0, `frpc --help=false status -c
/// CFG` exits 1 after dialling the config's `[webServer] port` (1 connection
/// counted by `accept`). bpaf has no such flag — `--help` is `Info::help_arg`,
/// `short('h').long("help")` (`bpaf-0.9.27/src/info.rs:41`), a flag the inner
/// parser never sees: when parsing fails, bpaf evaluates it and prints help
/// (`run_subparser`, `info.rs:281-301`), so at the base head the same argv
/// exited 0 with `status`'s bpaf usage (1604 B) on stdout and **0** connections
/// — `status` never ran.
///
/// The pass therefore removes every `--help=<bool>` token bpaf would otherwise
/// misread **whose first bare word is a command this binary implements**, and
/// keeps Go's meaning:
///
/// * `<bool>` false → the token is dropped and the rest of argv parses normally,
///   so `--help=false status` resolves `status` and runs it;
/// * `<bool>` true → `--help` (bare, the form bpaf short-circuits to help on) is
///   appended **at the end**, so the subcommand resolves first and prints *its*
///   help exactly as `frpc <sub> --help` does — which is the same document Go
///   prints for `--help=true <sub>` (measured on Go v0.71.0: `--help=true status`
///   and `status --help` are byte-identical, 627 B).
///
/// The "**whose first bare word is a command**" half is what keeps the pass from
/// making an argv *better than Go*. Two measured shapes, whose mechanisms differ:
///
/// * `frpc --help=true notacommand` is rc 1 with `unknown command "notacommand"
///   for "frpc"` (77 B on stderr): the `=`-attached form is a single token, so
///   cobra's `stripFlags` does not let it consume the next one, `notacommand` is
///   the first bare word, it is not a command, and `legacyArgs` refuses that word
///   before any parse. Removing the `--help=true` here would leave the same bare
///   word for bpaf, which answers with root help and rc 0.
/// * `frpc --help status` (bare) is rc 0 with the **root** help: there
///   `stripFlags` does let the unknown `--help` swallow `status`, so no bare word
///   survives and the root command runs.
///
/// So a token is dropped only when the argv's **first bare word** — the same word
/// [`hoist_leading_subcommand`] reads, with the values of value-taking flags
/// skipped the way cobra's `stripFlags` skips them — is a command this
/// [`RootCommand`] registers, or when there is no bare word at all (the band the
/// root-command divergence below already covers); otherwise it stays in argv and
/// bpaf's own reading is what prints. A bare word that is itself the value of a
/// value-taking flag does not count, so `frpc --help=true -c cfg` has no command
/// word and keeps bpaf's root help — the pre-existing `--help=false -c cfg`
/// divergence, unchanged by this pass (Go starts the client there: rc 124,
/// `TODO.md:4981`).
///
/// Values go through [`parse_go_bool`], i.e. Go's `strconv.ParseBool` spellings;
/// anything else is refused **here**, with pflag's own message and rc, rather
/// than being silently dropped. Note this refusal is **not** gated on the
/// subcommand test above: pflag rejects the value before cobra ever looks for a
/// command word, so `frpc --help=foo notacommand` is that error on Go too.
///
/// Surrounding behaviour that is deliberately left as it is: bare `--help`, `-h`
/// and `--help <word>` keep reaching bpaf exactly as before (`--help <word>`
/// consumes `<word>`, which is Go's own `stripFlags` reading — see
/// [`consumes_value`]). bpaf still decides **whether** a request is a help
/// request and builds the flag/usage model; the *document* printed for one is
/// rendered in cobra's shape by [`render_cobra_help`] — Go's own document byte
/// for byte on the two `verify` surfaces.
///
/// The bpaf argv after the `--help=<bool>` tokens have been resolved the way
/// pflag and cobra resolve them.
///
/// A token is a **request** only when pflag's walk reaches it as a flag
/// ([`walk_argv`]): `frpc -hc --help=false status` is the cluster's `c` taking
/// `--help=false` as its **value**, and `frpc --config --help=false status` is
/// the same for `--config`, so neither is a help request and both are copied
/// through untouched. Every `--help=<bool>` the walk leaves as a flag is then
/// resolved **last-wins** — Go's `flag.Value.Set` overwrites the bound bool, and
/// cobra reads it once at the end (`cobra-1.8.0/command.go:892-894`) — so
/// `--help=true --help=false status -c CFG` runs `status` (Go: rc 1 and **1
/// connection**, measured) where an "any true wins" reading would print help.
///
/// What happens to a flag the walk did reach:
///
/// * `<bool>` false → dropped, so the rest of argv parses normally and a
///   subcommand still resolves and **runs**;
/// * `<bool>` true → a bare `--help` is appended **at the end** — the subcommand
///   has already been hoisted to the front by then, so the *subcommand's* parser
///   sees it and prints that command's help, which is the same document
///   `frpc <sub> --help` prints (measured byte-identical to the base head's).
///
/// …but only when the argv contains a command word this binary implements.
/// Without one the tokens are left exactly where they are, which is the
/// pre-existing root divergence (`frpc --help=false -c cfg` starts the client on
/// Go, rc 124; both trees print root help here) and the reason
/// `frpc --help=true notacommand` keeps bpaf's answer instead of becoming root
/// help (Go refuses the word: `unknown command "notacommand" for "frpc"`, rc 1,
/// 77 B on stderr).
///
/// Values go through [`parse_go_bool`], i.e. Go's `strconv.ParseBool`
/// spellings; an out-of-grammar value is refused **here**, with pflag's line and
/// rc 1, rather than being silently dropped. That refusal is deliberately *not*
/// gated on the command-word test: pflag rejects the value before cobra looks
/// for a command at all, so `frpc --help=foo notacommand` is the same error on
/// Go.
///
/// No `-h<value>` spelling exists: pflag's `-h` is a bool, so `-hfalse` is a
/// shorthand cluster (`-h` plus `-f`/`-a`/…, which is `unknown shorthand flag` on
/// Go for whatever comes second) rather than a value, and `-h=false` reaches
/// **bpaf**, whose built-in help accepts the attached value and prints help:
/// `frpc -h=false -c cfg` is rc 0 help here and starts the client on Go
/// (`--help` is one of the two bools on both binaries this pass deliberately does
/// not model — see the root divergence above). Matching is exact-prefix —
/// `--help=falsex`, `--helpfalse` and `--helpful=x` are not `--help=<bool>` — and
/// a token after a real `--` is never touched.
fn expand_help_bool_value_form(argv: Vec<OsString>, root: RootCommand) -> Vec<OsString> {
    let context = ShortFlagContext::of(&argv, root);
    // The command word the hoist would have moved to the front, if any. Read
    // with pflag's value rule ([`consumes_the_next_token`]) rather than cobra's
    // `stripFlags` one, because this runs on the argv *after* the hoist: a
    // value-taking flag still owns the token after it.
    let first_bare_word_is_a_command = {
        let mut found = false;
        let mut index = 0;
        while index < argv.len() {
            let token = &argv[index];
            if token == "--" {
                break;
            }
            if token.to_string_lossy().starts_with('-') {
                index += if claims_the_next_token(token, context, root) {
                    2
                } else {
                    1
                };
                continue;
            }
            found = token
                .to_str()
                .is_some_and(|word| is_known_subcommand(word, root));
            break;
        }
        found
    };
    let walk = walk_argv(&argv, context, root);
    let mut seen_separator = false;
    let mut out = Vec::with_capacity(argv.len());
    let mut wanted_help = false;
    for (index, arg) in argv.iter().enumerate() {
        if seen_separator {
            out.push(arg.clone());
            continue;
        }
        if arg == "--" {
            seen_separator = true;
            out.push(arg.clone());
            continue;
        }
        let Some(text) = arg.to_str().and_then(|text| text.strip_prefix("--help=")) else {
            out.push(arg.clone());
            continue;
        };
        let Ok(value) = parse_go_bool(text.to_string()) else {
            eprintln!(
                "Error: invalid argument \"{text}\" for \"-h, --help\" flag: \
                 strconv.ParseBool: parsing \"{text}\": invalid syntax"
            );
            std::process::exit(1);
        };
        if walk.consumed[index] || !first_bare_word_is_a_command {
            // Either this token is another flag's value, or there is no command
            // for it to be about — both leave it exactly where it was.
            out.push(arg.clone());
            continue;
        }
        // Last wins, so a later token simply overwrites this one's decision.
        wanted_help = value;
    }
    if wanted_help {
        // Appended rather than pushed at the front: bpaf picks a branch before
        // dispatch, and a leading `--help` is a root flag that would pre-empt
        // the subcommand's own help (`frpc --help status` prints the ROOT help
        // on both Go and frp-rs — see `consumes_value`).
        out.push(OsString::from("--help"));
    }
    out
}

/// The bpaf argv for a process argv: `argv[0]` dropped the way
/// `Args::current_args` drops it (its file name is returned separately so help
/// and error output keep naming the program), and the pflag short-`=` alias
/// expanded.
///
/// `argv[0]` is dropped **here**, before every other pre-parse pass, because
/// the passes must classify exactly the tokens bpaf will classify: argv[0] is
/// not one of them, and a pass that sees it sees one spurious leading bare word
/// (which is how the first version of [`hoist_leading_subcommand`] managed to
/// never fire).
fn cli_args(argv: &[OsString]) -> (Option<String>, Vec<OsString>) {
    // Mirror `Args::current_args` exactly (`bpaf-0.9.27/src/args.rs:145-159`):
    // the name is argv[0]'s *file name* when it is valid UTF-8, and `None`
    // otherwise — never a hardcoded program name, which would make `frpc` print
    // `Usage: frps …` for an argv[0] bpaf cannot read.
    let name = argv
        .first()
        .map(std::path::Path::new)
        .and_then(std::path::Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .map(str::to_owned);
    let rest = expand_bool_short_value_form(argv.iter().skip(1).cloned().collect());
    (name, rest)
}

// ===========================================================================
// The `--help` document: cobra's, rendered from bpaf's parser metadata
// ===========================================================================
//
// Go frp prints **cobra's** help document; frp-rs printed bpaf's. The measured
// difference (TODO.md:253) is a different *document*, not merely a different
// layout: `frpc status --help` is 627 B of cobra — an `Overview of all proxies
// status` first line, a `Usage: frpc status [flags]` line, `Flags:` and
// `Global Flags:` sections aligned on a 30-column grid, `-h, --help  help for
// status` — against 1604 B of bpaf.
//
// [`render_cobra_help`] rebuilds that document from
//
// 1. the **surface**: `frps`/`frpc` itself, or one of its child commands,
//    derived from the argv [`prepared_cli_argv`] produced (`argv[0]` is the
//    command word cobra's `Find` would resolve, or a flag when the root is what
//    resolved), and
// 2. the **flag surface** of that command, read back out of bpaf's own help
//    rendering (`Doc::monochrome`) — so the rows cannot drift from the flags the
//    parser accepts, and the two-entries-per-bool shape bpaf prints
//    (`--strict-config=BOOL` beside `--strict-config`, the pair
//    [`go_bool_flag_impl`] builds) collapses to cobra's single row.
//
// bpaf cannot supply the flag *texts*: `bpaf::Item` is not nameable outside bpaf
// (`mod item` is private, `bpaf-0.9.27/src/lib.rs:182`) and `Metavar` has no
// public accessor (`bpaf-0.9.27/src/meta_help.rs:12`), so every row's varname and
// usage come from the tables below, measured on the released Go v0.71.0 binary.
//
// Only the two `verify` surfaces render byte-identically to Go's document; the
// other seven are **stated replacements**, because frp-rs's flag surface itself
// differs from Go's (different proxy flags, `frp-rs`-only log/admin flags, no
// `nathole`/`completion`/`help` commands). Printing a row for a flag the binary
// rejects, or hiding a flag it accepts, would be fake parity: the document
// describes what this binary actually parses.

/// One row of Go frp v0.71.0's pflag flag table.
///
/// `varname` is the pflag **type word** pflag prints after the flag name —
/// `string`, `int`, `duration`, `strings`, `stringToString` — not a metavar:
/// pflag derives it from the flag's `Value.Type()` (`UnquoteUsage`,
/// `pflag-1.0.5/flag.go`) and prints nothing at all for a bool. `usage` carries
/// pflag's ` (default …)` suffix verbatim when the flag's default is non-zero.
///
/// `short` is Go's shorthand. It is **checked against** the parser's, never
/// rendered from here: [`render_cobra_help`] debug-asserts that the parser's
/// shorthand for a rendered row equals Go's, so a row whose shorthand the parser
/// does not carry cannot silently become a rendered lie. Rows for flags frp-rs
/// does not implement at all (Go also registers `-r`/`-n` on `stcp`/`xtcp`,
/// `--allow-users`, `--sk` on `sudp`, and a dozen others) keep Go's shorthand
/// but are never rendered, because no parser flag names them.
#[derive(Clone, Copy, Debug)]
struct GoFlagRow {
    long: &'static str,
    short: Option<char>,
    varname: Option<&'static str>,
    usage: &'static str,
}

/// `frps`'s root flags, measured from the released Go frp **v0.71.0**
/// darwin/arm64 binary (`frps --help`, stdout, 2394 B). Order is pflag's own
/// (byte order of the long name, which is how the binary prints it, and how the
/// renderer sorts), so the table stays diffable against the measurement.
///
/// The set is exactly the flags `frps verify --help` repeats under
/// `Global Flags` — i.e. Go's persistent `rootCmd` set, and the list a row here
/// is *missing* from is the interesting half: a flag absent from this table is
/// either an frp-rs extension ([`FRPS_EXTENSION_FLAGS`]) or a flag frp-rs does
/// not have.
///
/// Two of Go's rows describe flags frp-rs registers only under a feature:
/// `--kcp-bind-port` (`#[cfg(feature = "kcp")]`) and `--quic-bind-port`
/// (`#[cfg(feature = "quic")]`) in [`svr_transport`]. They are gated here for
/// the same reason: a build without the feature does not register the flag, so
/// it is not part of that build's persistent set and must not be expected under
/// `Global Flags`. With frp-core's default features on all 29 rows are present,
/// which is the shape [`FRPS_GO_FLAGS`] was measured in.
const FRPS_GO_FLAGS: &[GoFlagRow] = &[
    GoFlagRow {
        long: "allow-ports",
        short: None,
        varname: Some("string"),
        usage: "allow ports",
    },
    GoFlagRow {
        long: "allow-unsafe",
        short: None,
        varname: Some("strings"),
        usage: "allowed unsafe features, one or more of: TokenSourceExec",
    },
    GoFlagRow {
        long: "bind-addr",
        short: None,
        varname: Some("string"),
        usage: "bind address (default \"0.0.0.0\")",
    },
    GoFlagRow {
        long: "bind-port",
        short: Some('p'),
        varname: Some("int"),
        usage: "bind port (default 7000)",
    },
    GoFlagRow {
        long: "config",
        short: Some('c'),
        varname: Some("string"),
        usage: "config file of frps",
    },
    GoFlagRow {
        long: "dashboard-addr",
        short: None,
        varname: Some("string"),
        usage: "dashboard address (default \"0.0.0.0\")",
    },
    GoFlagRow {
        long: "dashboard-port",
        short: None,
        varname: Some("int"),
        usage: "dashboard port",
    },
    GoFlagRow {
        long: "dashboard-pwd",
        short: None,
        varname: Some("string"),
        usage: "dashboard password (default \"admin\")",
    },
    GoFlagRow {
        long: "dashboard-tls-cert-file",
        short: None,
        varname: Some("string"),
        usage: "dashboard tls cert file",
    },
    GoFlagRow {
        long: "dashboard-tls-key-file",
        short: None,
        varname: Some("string"),
        usage: "dashboard tls key file",
    },
    GoFlagRow {
        long: "dashboard-tls-mode",
        short: None,
        varname: None,
        usage: "if enable dashboard tls mode",
    },
    GoFlagRow {
        long: "dashboard-user",
        short: None,
        varname: Some("string"),
        usage: "dashboard user (default \"admin\")",
    },
    GoFlagRow {
        long: "disable-log-color",
        short: None,
        varname: None,
        usage: "disable log color in console",
    },
    GoFlagRow {
        long: "enable-prometheus",
        short: None,
        varname: None,
        usage: "enable prometheus dashboard",
    },
    #[cfg(feature = "kcp")]
    GoFlagRow {
        long: "kcp-bind-port",
        short: None,
        varname: Some("int"),
        usage: "kcp bind udp port",
    },
    GoFlagRow {
        long: "log-file",
        short: None,
        varname: Some("string"),
        usage: "log file (default \"console\")",
    },
    GoFlagRow {
        long: "log-level",
        short: None,
        varname: Some("string"),
        usage: "log level (default \"info\")",
    },
    GoFlagRow {
        long: "log-max-days",
        short: None,
        varname: Some("int"),
        usage: "log max days (default 3)",
    },
    GoFlagRow {
        long: "max-ports-per-client",
        short: None,
        varname: Some("int"),
        usage: "max ports per client",
    },
    GoFlagRow {
        long: "proxy-bind-addr",
        short: None,
        varname: Some("string"),
        usage: "proxy bind address (default \"0.0.0.0\")",
    },
    #[cfg(feature = "quic")]
    GoFlagRow {
        long: "quic-bind-port",
        short: None,
        varname: Some("int"),
        usage: "quic bind udp port",
    },
    GoFlagRow {
        long: "strict-config",
        short: None,
        varname: None,
        usage: "strict config parsing mode, unknown fields will cause errors (default true)",
    },
    GoFlagRow {
        long: "subdomain-host",
        short: None,
        varname: Some("string"),
        usage: "subdomain host",
    },
    GoFlagRow {
        long: "tls-only",
        short: None,
        varname: None,
        usage: "frps tls only",
    },
    GoFlagRow {
        long: "token",
        short: Some('t'),
        varname: Some("string"),
        usage: "auth token",
    },
    GoFlagRow {
        long: "version",
        short: Some('v'),
        varname: None,
        usage: "version of frps",
    },
    GoFlagRow {
        long: "vhost-http-port",
        short: None,
        varname: Some("int"),
        usage: "vhost http port",
    },
    GoFlagRow {
        long: "vhost-http-timeout",
        short: None,
        varname: Some("int"),
        usage: "vhost http response header timeout (default 60)",
    },
    GoFlagRow {
        long: "vhost-https-port",
        short: None,
        varname: Some("int"),
        usage: "vhost https port",
    },
];

/// `frpc`'s persistent root flags, measured the same way (`frpc --help`,
/// 1370 B; `frpc verify --help` repeats exactly these under `Global Flags`).
const FRPC_ROOT_GO_FLAGS: &[GoFlagRow] = &[
    GoFlagRow {
        long: "allow-unsafe",
        short: None,
        varname: Some("strings"),
        usage: "allowed unsafe features, one or more of: TokenSourceExec",
    },
    GoFlagRow {
        long: "config",
        short: Some('c'),
        varname: Some("string"),
        usage: "config file of frpc (default \"./frpc.ini\")",
    },
    GoFlagRow {
        long: "config-dir",
        short: None,
        varname: Some("string"),
        usage: "config directory, run one frpc service for each file in config directory",
    },
    GoFlagRow {
        long: "strict-config",
        short: None,
        varname: None,
        usage: "strict config parsing mode, unknown fields will cause an errors (default true)",
    },
    GoFlagRow {
        long: "version",
        short: Some('v'),
        varname: None,
        usage: "version of frpc",
    },
];

/// The `status`/`reload`/`stop` flags Go registers on the command itself
/// (`cmd/frpc/sub/admin.go`): one row, `--api-timeout`.
const FRPC_ADMIN_GO_FLAGS: &[GoFlagRow] = &[GoFlagRow {
    long: "api-timeout",
    short: None,
    varname: Some("duration"),
    usage: "Timeout for admin API calls (default 30s)",
}];

/// The union of the eight single-proxy commands' own flags on Go v0.71.0
/// (`frpc tcp --help` 2211 B and `frpc https --help` 2269 B, minus `-h`).
///
/// frp-rs's proxy parsers accept a smaller set than Go's, so many of these rows
/// are never looked up — the table is the *lookup* source, not the surface. The
/// rows frp-rs spells differently from Go (`--custom-domain`, `--sd`, `--mux`,
/// `--remote-port`, `--tls-server-name`, `--uc`, `--ue`) all take **Go's**
/// spelling as the primary now; the older frp-rs spellings survive as hidden
/// bpaf aliases, which never render. The only row frp-rs adds of its own is
/// tcpmux's `--mux-port`, in [`FRPC_PROXY_EXTENSION_FLAGS`].
const FRPC_PROXY_GO_FLAGS: &[GoFlagRow] = &[
    GoFlagRow {
        long: "allow-users",
        short: None,
        varname: Some("strings"),
        usage: "allow visitor users",
    },
    GoFlagRow {
        long: "annotations",
        short: None,
        varname: Some("stringToString"),
        usage: "annotation key-value pairs (e.g., key1=value1,key2=value2) (default [])",
    },
    GoFlagRow {
        long: "bandwidth-limit",
        short: None,
        varname: Some("string"),
        usage: "bandwidth limit (e.g. 100KB or 1MB)",
    },
    GoFlagRow {
        long: "bandwidth-limit-mode",
        short: None,
        varname: Some("string"),
        usage: "bandwidth limit mode (default \"client\")",
    },
    GoFlagRow {
        long: "client-id",
        short: None,
        varname: Some("string"),
        usage: "unique identifier for this frpc instance",
    },
    GoFlagRow {
        long: "custom-domain",
        short: Some('d'),
        varname: Some("strings"),
        usage: "custom domains",
    },
    GoFlagRow {
        long: "disable-log-color",
        short: None,
        varname: None,
        usage: "disable log color in console",
    },
    GoFlagRow {
        long: "dns-server",
        short: None,
        varname: Some("string"),
        usage: "specify dns server instead of using system default one",
    },
    GoFlagRow {
        long: "host-header-rewrite",
        short: None,
        varname: Some("string"),
        usage: "host header rewrite",
    },
    GoFlagRow {
        long: "http-pwd",
        short: None,
        varname: Some("string"),
        usage: "http auth password",
    },
    GoFlagRow {
        long: "http-user",
        short: None,
        varname: Some("string"),
        usage: "http auth user",
    },
    GoFlagRow {
        long: "local-ip",
        short: Some('i'),
        varname: Some("string"),
        usage: "local ip (default \"127.0.0.1\")",
    },
    GoFlagRow {
        long: "local-port",
        short: Some('l'),
        varname: Some("int"),
        usage: "local port",
    },
    GoFlagRow {
        long: "locations",
        short: None,
        varname: Some("strings"),
        usage: "locations",
    },
    GoFlagRow {
        long: "log-file",
        short: None,
        varname: Some("string"),
        usage: "console or file path (default \"console\")",
    },
    GoFlagRow {
        long: "log-level",
        short: None,
        varname: Some("string"),
        usage: "log level (default \"info\")",
    },
    GoFlagRow {
        long: "log-max-days",
        short: None,
        varname: Some("int"),
        usage: "log file reversed days (default 3)",
    },
    GoFlagRow {
        long: "metadatas",
        short: None,
        varname: Some("stringToString"),
        usage: "metadata key-value pairs (e.g., key1=value1,key2=value2) (default [])",
    },
    GoFlagRow {
        long: "mux",
        short: None,
        varname: Some("string"),
        usage: "multiplexer",
    },
    GoFlagRow {
        long: "protocol",
        short: Some('p'),
        varname: Some("string"),
        usage: "optional values are [tcp kcp quic websocket wss] (default \"tcp\")",
    },
    GoFlagRow {
        long: "proxy-name",
        short: Some('n'),
        varname: Some("string"),
        usage: "proxy name",
    },
    GoFlagRow {
        long: "remote-port",
        short: Some('r'),
        varname: Some("int"),
        usage: "remote port",
    },
    GoFlagRow {
        long: "sd",
        short: None,
        varname: Some("string"),
        usage: "sub domain",
    },
    GoFlagRow {
        long: "server-addr",
        short: Some('s'),
        varname: Some("string"),
        usage: "frp server's address (default \"127.0.0.1\")",
    },
    GoFlagRow {
        long: "server-port",
        short: Some('P'),
        varname: Some("int"),
        usage: "frp server's port (default 7000)",
    },
    GoFlagRow {
        long: "sk",
        short: None,
        varname: Some("string"),
        usage: "secret key",
    },
    GoFlagRow {
        long: "tls-enable",
        short: None,
        varname: None,
        usage: "enable frpc tls (default true)",
    },
    GoFlagRow {
        long: "tls-server-name",
        short: None,
        varname: Some("string"),
        usage: "specify the custom server name of tls certificate",
    },
    GoFlagRow {
        long: "token",
        short: Some('t'),
        varname: Some("string"),
        usage: "auth token",
    },
    GoFlagRow {
        long: "uc",
        short: None,
        varname: None,
        usage: "use compression",
    },
    GoFlagRow {
        long: "ue",
        short: None,
        varname: None,
        usage: "use encryption",
    },
    GoFlagRow {
        long: "user",
        short: Some('u'),
        varname: Some("string"),
        usage: "user",
    },
];

/// frp-rs flags on `frps` that Go v0.71.0 has no row for: the two the run path
/// adds beside Go's surface. Their usage text is frp-rs's own (the config
/// defaults they fall back to are stated the way pflag states its defaults).
const FRPS_EXTENSION_FLAGS: &[GoFlagRow] = &[
    GoFlagRow {
        long: "config-dir",
        short: None,
        varname: Some("string"),
        usage: "config directory, run one frps service for each file in config directory",
    },
    GoFlagRow {
        long: "log-format",
        short: None,
        varname: Some("string"),
        usage: "log format (default \"text\")",
    },
];

/// frp-rs flags on the `frpc` root that Go's `frpc` does not register: measured
/// on Go v0.71.0, `frpc --log-file x --help`, `--log-level`, `--log-max-days`,
/// `--log-format` and `--disable-log-color` are all `unknown flag` there.
const FRPC_ROOT_EXTENSION_FLAGS: &[GoFlagRow] = &[
    GoFlagRow {
        long: "log-file",
        short: None,
        varname: Some("string"),
        usage: "log file (default \"console\")",
    },
    GoFlagRow {
        long: "log-level",
        short: Some('L'),
        varname: Some("string"),
        usage: "log level (default \"info\")",
    },
    GoFlagRow {
        long: "log-max-days",
        short: None,
        varname: Some("int"),
        usage: "log max days (default 3)",
    },
    GoFlagRow {
        long: "log-format",
        short: None,
        varname: Some("string"),
        usage: "log format (default \"text\")",
    },
    GoFlagRow {
        long: "disable-log-color",
        short: None,
        varname: None,
        usage: "disable log color in console",
    },
];

/// frp-rs flags on `frpc status`/`reload`/`stop` that Go has no row for. Go's
/// admin commands reach the same API through the config file and register only
/// `--api-timeout`, so these five are frp-rs extensions on every one of the
/// three (`--json` on `status` only).
const FRPC_ADMIN_EXTENSION_FLAGS: &[GoFlagRow] = &[
    GoFlagRow {
        long: "admin-addr",
        short: None,
        varname: Some("string"),
        usage: "admin address",
    },
    GoFlagRow {
        long: "admin-port",
        short: None,
        varname: Some("int"),
        usage: "admin port",
    },
    GoFlagRow {
        long: "admin-pwd",
        short: None,
        varname: Some("string"),
        usage: "admin password",
    },
    GoFlagRow {
        long: "admin-user",
        short: None,
        varname: Some("string"),
        usage: "admin user",
    },
    GoFlagRow {
        long: "json",
        short: None,
        varname: None,
        usage: "Output the status as JSON",
    },
];

/// frp-rs's own flags on the single-proxy commands — the rows Go has no
/// equivalent of.
///
/// This table used to carry frp-rs spellings for Go's `--custom-domain`,
/// `--sd`, `--mux`, `--remote-port`, `--tls-server-name`, `--uc` and `--ue`
/// too. None of those are needed now: the parser takes **Go's** spelling as the
/// primary on every one of those rows (the old spellings are hidden bpaf
/// aliases, which never render), so they come from [`FRPC_PROXY_GO_FLAGS`] —
/// including Go's `strings` type word for `--custom-domain`, which this parser
/// takes exactly once (the same "Go's word, narrower grammar" convention as
/// `--locations`). What stays here is what Go has no row for: frp-rs's own
/// tcpmux `--mux-port`.
///
/// Sudp's long-only `--remote-port` is the one extension that does **not** get
/// a row here: Go has a `remote-port` row (its tcp/udp one), and the renderer
/// takes every row's `varname`/`usage` from the table, so that row already
/// supplies the text. What makes sudp's copy an extension is the *absence of a
/// shorthand*, which comes from the parser (no `.short('r')`), not from a row.
const FRPC_PROXY_EXTENSION_FLAGS: &[GoFlagRow] = &[
    // frp-rs's own tcpmux port. Go's `frpc tcpmux` has no port flag at all
    // (measured: its help has no `--remote-port` row), and frp-rs's server never
    // reads a tcpmux proxy's `remote_port`, so this exists only for command
    // lines written against it — hence the row, and hence `optional` in
    // [`tcpmux_cmd`].
    GoFlagRow {
        long: "mux-port",
        short: None,
        varname: Some("int"),
        usage: "multiplexer port",
    },
];

/// Go's root-command description line (`rootCmd.Short`), which cobra prints
/// first, followed by a blank line. Measured on the released v0.71.0 binary;
/// frp-rs's own `.descr()` says `frp-rs` where Go says `frp`, and the document
/// is Go's — the parser's `.descr()` is a separate, untouched string.
const FRPS_DESCR: &str = "frps is the server of frp (https://github.com/fatedier/frp)";
const FRPC_DESCR: &str = "frpc is the client of frp (https://github.com/fatedier/frp)";

/// Go's `Short` text for each implemented child command, as both the
/// `Available Commands:` line and (for a leaf) the document's first line.
///
/// `Verify that the configures is valid` is **Go's own typo** — it reads
/// "configures" for "configuration" — and it is what the released v0.71.0
/// binary prints on `frps verify --help` and `frpc verify --help` alike. Those
/// two documents are the byte-exact witness for this layer, so the typo is
/// load-bearing: do not "fix" it.
const FRPS_COMMAND_SHORTS: &[(&str, &str)] = &[("verify", "Verify that the configures is valid")];

const FRPC_COMMAND_SHORTS: &[(&str, &str)] = &[
    ("http", "Run frpc with a single http proxy"),
    ("https", "Run frpc with a single https proxy"),
    ("reload", "Hot-Reload frpc configuration"),
    ("status", "Overview of all proxies status"),
    ("stcp", "Run frpc with a single stcp proxy"),
    ("stop", "Stop the running frpc"),
    ("sudp", "Run frpc with a single sudp proxy"),
    ("tcp", "Run frpc with a single tcp proxy"),
    ("tcpmux", "Run frpc with a single tcpmux proxy"),
    ("udp", "Run frpc with a single udp proxy"),
    ("verify", "Verify that the configures is valid"),
    ("xtcp", "Run frpc with a single xtcp proxy"),
];

/// The root command's own name, as cobra's `Use`/`Name()` spells it. Never
/// argv[0]: the document names the command, not the path it was invoked by.
fn root_name(root: RootCommand) -> &'static str {
    match root {
        RootCommand::Frps => "frps",
        RootCommand::Frpc => "frpc",
    }
}

fn root_descr(root: RootCommand) -> &'static str {
    match root {
        RootCommand::Frps => FRPS_DESCR,
        RootCommand::Frpc => FRPC_DESCR,
    }
}

/// Go's short text for one of this root's commands; empty when the command has
/// no measured text (which the module tests reject).
fn command_short(root: RootCommand, command: &str) -> &'static str {
    let table = match root {
        RootCommand::Frps => FRPS_COMMAND_SHORTS,
        RootCommand::Frpc => FRPC_COMMAND_SHORTS,
    };
    table
        .iter()
        .find(|(name, _)| *name == command)
        .map_or("", |(_, short)| *short)
}

/// The flags cobra registers **persistently** on this root — the ones every
/// child command inherits and prints under `Global Flags`. Measured: `frps
/// verify --help` repeats all 29 [`FRPS_GO_FLAGS`] longs there and `frpc verify
/// --help` all 5 [`FRPC_ROOT_GO_FLAGS`] longs, both ways (module test). The
/// frps table is the compiled surface, so a build without `kcp`/`quic` repeats
/// 27 longs there, not 29.
fn root_persistent_flags(root: RootCommand) -> &'static [GoFlagRow] {
    match root {
        RootCommand::Frps => FRPS_GO_FLAGS,
        RootCommand::Frpc => FRPC_ROOT_GO_FLAGS,
    }
}

/// The tables whose rows may describe one surface, in lookup order: the first
/// table with the long name wins, so a surface's own rows shadow the root's.
///
/// The `frpc` admin surfaces consult the proxy table not at all and the root's
/// tables last; the proxy surfaces take their own union first. An frp-rs flag
/// with no Go counterpart is found in the matching `*_EXTENSION_FLAGS` table,
/// and a flag in none of them renders with an empty usage — which is a test
/// failure, not a silently narrower document.
fn help_flag_tables(root: RootCommand, command: Option<&str>) -> Vec<&'static [GoFlagRow]> {
    match (root, command) {
        (RootCommand::Frps, _) => vec![FRPS_GO_FLAGS, FRPS_EXTENSION_FLAGS],
        (RootCommand::Frpc, None | Some("verify")) => {
            vec![FRPC_ROOT_GO_FLAGS, FRPC_ROOT_EXTENSION_FLAGS]
        }
        (RootCommand::Frpc, Some("status" | "reload" | "stop")) => vec![
            FRPC_ADMIN_GO_FLAGS,
            FRPC_ADMIN_EXTENSION_FLAGS,
            FRPC_ROOT_GO_FLAGS,
            FRPC_ROOT_EXTENSION_FLAGS,
        ],
        (RootCommand::Frpc, Some(_proxy)) => vec![
            FRPC_PROXY_GO_FLAGS,
            FRPC_PROXY_EXTENSION_FLAGS,
            FRPC_ROOT_GO_FLAGS,
            FRPC_ROOT_EXTENSION_FLAGS,
        ],
    }
}

/// Go's row for `long` on this surface, if there is one.
fn go_flag_row(tables: &[&'static [GoFlagRow]], long: &str) -> Option<&'static GoFlagRow> {
    tables
        .iter()
        .find_map(|table| table.iter().find(|row| row.long == long))
}

/// A flag as bpaf's own help rendering exposes it.
///
/// `bool_switch` is true when **any** spelling of the long name is a bare
/// switch: bpaf prints the value entry (`--strict-config=BOOL`) and the switch
/// entry (`--strict-config`) of [`go_bool_flag_impl`]'s pair as two lines, and
/// cobra has one row for the flag.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BpafFlag {
    long: String,
    short: Option<char>,
    bool_switch: bool,
}

/// A flag row ready to print: the parser's shorthand, plus pflag's varname
/// (`None` for a bool — pflag prints no type word for one) and usage.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RenderedFlag {
    long: String,
    short: Option<char>,
    varname: Option<&'static str>,
    usage: String,
}

/// Read a command's flag surface back out of bpaf's own help rendering.
///
/// bpaf emits one option line per *spelling*, so the rows are merged by
/// canonical long name: Go's `WordSepNormalizeFunc` rewrites every `_` to `-`
/// before a lookup (`pkg/config/flags.go:31-36`), which is why `--config_dir`
/// and `--config-dir` are one flag for pflag and one row here. `--help` is
/// dropped, not merged: cobra synthesizes `-h, --help` per command, so it is
/// not part of the surface this function is describing.
///
/// A flag line is recognised positionally, which is how bpaf emits it: the long
/// token begins at column 8 (`    -x, ` or four blanks), while a wrapped usage
/// continuation is indented to the usage column (always > 8) and anything else
/// in the document — `Available commands:` entries, subsection headers,
/// positional items — sits at a different column. Order of first appearance is
/// preserved; the caller sorts.
fn bpaf_help_flags(doc: &Doc) -> Vec<BpafFlag> {
    let mut flags: Vec<BpafFlag> = Vec::new();
    for line in doc.monochrome(true).lines() {
        let Some(head) = line.get(..8) else { continue };
        let short = match head.as_bytes() {
            [b' ', b' ', b' ', b' ', b'-', short, b',', b' '] => Some(*short as char),
            bytes if bytes.iter().all(|byte| *byte == b' ') => None,
            _ => continue,
        };
        let Some(rest) = line.get(8..) else { continue };
        if !rest.starts_with("--") {
            continue;
        }
        // `--long` or `--long=VARNAME`; the usage text follows after a run of
        // blanks, so splitting at the first blank isolates the flag token.
        let word = rest.split(' ').next().unwrap_or(rest);
        let (name, has_varname) = match word.split_once('=') {
            Some((name, _)) => (name, true),
            None => (word, false),
        };
        let long = name.trim_start_matches("--").replace('_', "-");
        if long == "help" {
            continue;
        }
        match flags.iter_mut().find(|flag| flag.long == long) {
            Some(flag) => {
                flag.short = flag.short.or(short);
                flag.bool_switch |= !has_varname;
            }
            None => flags.push(BpafFlag {
                long,
                short,
                bool_switch: !has_varname,
            }),
        }
    }
    flags
}

/// pflag's `FlagUsagesWrapped(0)` line prefix for one flag: `  -x, --long` when
/// the parser has a shorthand, four blanks and `--long` when it does not, then
/// the type word.
fn flag_prefix(flag: &RenderedFlag) -> String {
    let mut prefix = match flag.short {
        Some(short) => format!("  -{short}, --{}", flag.long),
        None => format!("      --{}", flag.long),
    };
    if let Some(varname) = flag.varname {
        prefix.push(' ');
        prefix.push_str(varname);
    }
    prefix
}

/// pflag's `FlagUsagesWrapped(0)`: one line per flag, each prefix padded to one
/// blank past the longest prefix of its block (`maxlen = max(len(prefix) + 1)`
/// in `pflag-1.0.5/flag.go`, printed as `prefix`, `maxlen - len(prefix)` blanks,
/// usage), which is the 30-column grid the measured documents show.
///
/// The caller sorts by long name first: pflag sorts its own list that way
/// (`--tls-only`, `--token`, `--version`, `--vhost-http-port` on `frps --help`),
/// *not* by a union with the shorthands. A row with no usage still gets its
/// blanks, exactly as pflag's `Fprintln` writes them; cobra's
/// `trimTrailingWhitespaces` then trims only the end of the block, which is why
/// the document has no trailing blank line. No measured surface has such a row
/// (module test).
fn flag_usages(flags: &[RenderedFlag]) -> String {
    let prefixes: Vec<String> = flags.iter().map(flag_prefix).collect();
    let longest = prefixes.iter().map(String::len).max().unwrap_or(0);
    let mut out = String::new();
    for (prefix, flag) in prefixes.iter().zip(flags) {
        out.push_str(prefix);
        for _ in 0..(longest - prefix.len() + 3) {
            out.push(' ');
        }
        out.push_str(&flag.usage);
        out.push('\n');
    }
    out
}

/// Render cobra's help document for `command` (the root when `None`) from the
/// `Doc` bpaf produced for that command, in the shape the released Go v0.71.0
/// binary prints.
///
/// The template is cobra's usage template with every branch measured on the
/// oracle: an optional description line and blank line, `Usage:` plus the
/// `UseLine` (and, for a root with commands, a second `<name> [command]` line),
/// `Available Commands:` padded to `max(11, longest name)`, `Flags:` (the
/// surface's own flags plus cobra's synthesized `-h, --help`) and `Global
/// Flags:` (the root's persistent set), and — for a root only — cobra's
/// `Use "… [command] --help"` footer. cobra's `trimTrailingWhitespaces` on the
/// flag blocks is `trim_end` here, and the document ends with exactly one `\n`.
///
/// The rendered document describes **this** binary's surface: a row is printed
/// only for a flag bpaf actually accepted, and a flag with no row prints with an
/// empty usage (a test failure, never a shipped document).
fn render_cobra_help(root: RootCommand, command: Option<&str>, doc: &Doc) -> String {
    let name = root_name(root);
    let flags = bpaf_help_flags(doc);
    let tables = help_flag_tables(root, command);
    let persistent = root_persistent_flags(root);
    let own_name = command.unwrap_or(name);

    let mut local: Vec<RenderedFlag> = Vec::new();
    let mut global: Vec<RenderedFlag> = Vec::new();
    for flag in &flags {
        let row = go_flag_row(&tables, &flag.long);
        // Go's shorthand is an invariant to check, never the value to print.
        // Where the parser has one it must be Go's — that is what keeps the two
        // `verify` documents byte-exact (`frps -c/-p/-t/-v`) — but the converse
        // does not hold: frp-rs never implemented `frpc tcp`'s `-i/-l/-r/-s/-P/-n`,
        // and the document must not advertise a shorthand the parser rejects.
        debug_assert!(
            flag.short.is_none() || row.is_none_or(|row| row.short == flag.short),
            "the parser's shorthand for --{} is {:?}, which is not Go's {:?}",
            flag.long,
            flag.short,
            row.and_then(|row| row.short)
        );
        let rendered = RenderedFlag {
            long: flag.long.clone(),
            short: flag.short,
            varname: if flag.bool_switch {
                None
            } else {
                row.and_then(|row| row.varname)
            },
            usage: row.map_or("", |row| row.usage).to_owned(),
        };
        if command.is_some() && persistent.iter().any(|row| row.long == flag.long) {
            global.push(rendered);
        } else {
            local.push(rendered);
        }
    }
    // cobra's built-in help flag, local to every command and named after the
    // command it describes (`help for frps`, `help for verify`).
    local.push(RenderedFlag {
        long: "help".to_owned(),
        short: Some('h'),
        varname: None,
        usage: format!("help for {own_name}"),
    });
    local.sort_by(|a, b| a.long.cmp(&b.long));
    global.sort_by(|a, b| a.long.cmp(&b.long));

    let mut out = String::new();
    let descr = match command {
        Some(command) => command_short(root, command),
        None => root_descr(root),
    };
    if !descr.is_empty() {
        out.push_str(descr);
        out.push_str("\n\n");
    }
    let path = match command {
        Some(command) => format!("{name} {command}"),
        None => name.to_owned(),
    };
    out.push_str("Usage:\n  ");
    out.push_str(&path);
    out.push_str(" [flags]");

    let mut commands = root.subcommands().to_vec();
    commands.sort_unstable();
    if command.is_none() && !commands.is_empty() {
        out.push_str("\n  ");
        out.push_str(name);
        out.push_str(" [command]");
        out.push_str("\n\nAvailable Commands:");
        let padding = commands
            .iter()
            .map(|name| name.len())
            .max()
            .unwrap_or(0)
            .max(11);
        for command in commands {
            out.push_str(&format!(
                "\n  {command:<padding$} {}",
                command_short(root, command)
            ));
        }
    }
    if !local.is_empty() {
        out.push_str("\n\nFlags:\n");
        out.push_str(flag_usages(&local).trim_end());
    }
    if !global.is_empty() {
        out.push_str("\n\nGlobal Flags:\n");
        out.push_str(flag_usages(&global).trim_end());
    }
    if command.is_none() && !root.subcommands().is_empty() {
        out.push_str(&format!(
            "\n\nUse \"{name} [command] --help\" for more information about a command."
        ));
    }
    out.push('\n');
    out
}

/// What a help request is about: the binary's root command, plus the child
/// command word the prepared argv resolved, if any.
#[derive(Clone, Copy, Debug)]
struct HelpRequest {
    root: RootCommand,
    command: Option<&'static str>,
}

/// The surface [`render_cobra_help`] renders for this argv.
///
/// `argv` is the argv [`prepared_cli_argv`] produced, in which the resolved
/// subcommand — when there is one — is at index 0, exactly the word cobra's
/// `Find` would resolve. `--help <word>` has already been resolved to the root
/// by then (measured: `frpc --help status` prints the *root* document on both
/// Go and frp-rs, while `frpc --help=true status` prints `status`'s).
fn help_request(root: RootCommand, argv: &[OsString]) -> HelpRequest {
    let command = argv
        .first()
        .and_then(|token| token.to_str())
        .and_then(|word| {
            root.subcommands()
                .iter()
                .copied()
                .find(|name| *name == word)
        });
    HelpRequest { root, command }
}

/// Run an `OptionParser` over the argv [`cli_args`] produced and exit the way
/// `OptionParser::run` does (`err.print_message(self.info.max_width)`, then
/// `err.exit_code()`) — except for a help request, which is printed as cobra's
/// document ([`render_cobra_help`]) instead of bpaf's.
///
/// `help` names the surface to render when `rest` is a `--help` invocation.
/// A help request is the **only** stdout failure bpaf can produce here: frp-rs
/// disables bpaf's `help_if_no_args` (a bare `frps`/`frpc` runs), and the
/// `autocomplete` feature that `ParseFailure::Completion` requires is off, so
/// `ParseFailure::Stdout` is exactly the document to replace.
fn run_cli<T>(
    parser: bpaf::OptionParser<T>,
    name: Option<String>,
    rest: &[OsString],
    help: HelpRequest,
) -> T {
    let args = bpaf::Args::from(rest);
    // `set_name` only when there *is* one: `Args::current_args` leaves the name
    // unset for an unreadable argv[0], and bpaf renders that case differently.
    let args = match &name {
        Some(name) => args.set_name(name),
        None => args,
    };
    match parser.run_inner(args) {
        Ok(value) => value,
        Err(err) => {
            if let bpaf::ParseFailure::Stdout(doc, _) = &err {
                print!("{}", render_cobra_help(help.root, help.command, doc));
                std::process::exit(0);
            }
            err.print_message(CLI_OUTPUT_WIDTH);
            std::process::exit(err.exit_code());
        }
    }
}

/// The argv a binary's entry point hands bpaf, built from the argv
/// [`cli_args`] produced (`argv[0]` already dropped, `-v=` alias already
/// expanded), with the pre-parse passes applied in the one order that
/// composes:
///
/// 1. [`rewrite_config_dash_values`] — pflag's config dash-value rule.
/// 2. [`hoist_leading_subcommand`] — cobra's command resolution, on the root
///    command named by `root`. **Both** binaries have a hoistable root: Go's
///    `frps` registers a child command (`rootCmd.AddCommand(verifyCmd)`,
///    `cmd/frps/verify.go:29`) beside cobra's own `completion`/`help`, and
///    `frps --help` lists all three under `Available Commands` (measured on Go
///    v0.71.0). The claim this comment used to carry — "Go's `frps` declares no
///    subcommands" — was false, and `frps` is now hoisted exactly like `frpc`,
///    from its own measured flag/command set ([`RootCommand`]).
///
/// Both entry points call **this** function, which is what makes the shared
/// pass a single decision rather than two call sites that could drift:
/// [`parse_frps_args`] and [`parse_frpc_args`] differ only in which parser they
/// run over the result and in the [`RootCommand`] they name. Crate-private: the
/// module's tests pin the chain (this preparation, then the parser) through it,
/// so they follow the same expression the binaries use instead of calling a pass
/// directly — see `frps_takes_a_dash_shaped_config_value`.
///
/// **The passes, in order** (each one's own doc has the measurements):
///
/// 1. [`rewrite_config_dash_values`] — the pre-existing config dash-value rewrite.
/// 2. [`attach_flag_shaped_values`] — a flag-shaped value is joined to its flag
///    with `=`, the only spelling bpaf parses as a value. Its consumer test is
///    [`consumes_value`] (the same cobra-shaped one the walk uses), so it covers
///    the long flags too: `frps verify --token --help=false -c CFG` must give
///    `--help=false` to `--token`.
/// 3. [`hoist_leading_subcommand`] — cobra's command resolution.
/// 4. [`expand_help_bool_value_form`] — `--help=<bool>` resolved last-wins and
///    dropped (or turned into a trailing bare `--help`) only when a command word
///    follows.
/// 5. [`reject_pflag_shorthand_cluster_that_needs_a_value`] — pflag's refusal for
///    the argv the passes above left unreachable.
///
/// **Why the rewrite runs first.** The hoist classifies tokens as flag / value /
/// bare word, and it has to classify the argv the parser will actually see —
/// which, on Go, is the argv *after* pflag's value rule has already been
/// applied inside pflag, not a separate pre-pass. `-c -- status` is the shape
/// that shows the difference: the rewrite turns `--` into `-c`'s **value**
/// (`-c=--`), so by the time the hoist looks there is no separator left and
/// `status` is the first bare word — measured on Go v0.71.0,
/// `frpc -c -- status` resolves the `status` subcommand (that is why the config
/// is even read) and fails on `open --: no such file or directory`, rc 1.
/// Running the hoist on the raw argv instead would see a `--` separator and
/// leave `status` un-hoisted, producing frp-rs's pre-existing ``no such command
/// or positional: `status` ``. The reverse order (hoist, then rewrite) would
/// decide before `--`-as-value is known, and could move a token across what is
/// still a real separator.
///
/// **Why the two `--help` passes are where they are.** Both run on the
/// rewritten argv, and neither may look at a token the rewrite has already
/// consumed: measured, `frpc -c --help` is `-c`'s value on Go (`open --help: no
/// such file or directory`, rc 1), and the rewrite is what makes frp-rs take the
/// same path — a `--help` pass running before it would turn that argv into help
/// again. Beyond that:
///
/// * [`reject_pflag_shorthand_cluster_that_needs_a_value`] runs **after** the
///   hoist, and that order is load-bearing. The rule needs to know what is left
///   of argv once cobra's `Find` has taken the command word out of it: measured
///   on Go v0.71.0, `frpc -hc status` is the cluster with `status` **removed**
///   (so `-c` has nothing and the error is Go's rc 1), while
///   `frpc -hc status -c CFG` keeps `CFG` for `-c` (rc 0, `status`'s help) — and
///   `frpc -hc status -c` has `-c` dangling, again Go's error. The distinction is
///   exactly the hoisted remainder's tail, so the detector reads
///   [`hoist_leading_subcommand`]'s output rather than inventing its own
///   candidate-word scan.
/// * [`expand_help_bool_value_form`] runs **after that**, so that a
///   `--help=false` still in argv has already been dropped before the detector
///   decides what the last token is: measured on Go v0.71.0,
///   `frpc -hc --help=false status` is rc 1 with the missing-argument error,
///   because `--help=false` set no value for `-c` — the detector must see
///   `["-hc"]`, not `["-hc", "--help=false"]`.
/// * and it runs after the hoist for the other reason spelled out next: the
///   bare `--help` it appends has to be read by the subcommand's parser, so
///   `--help=true status -c CFG` becomes `status -c CFG --help` (Go's `status`
///   help) rather than a leading root `--help` (the root help).
fn prepared_cli_argv(rest: &[OsString], root: RootCommand) -> Vec<OsString> {
    let rewritten = rewrite_config_dash_values(rest);
    let attached = attach_flag_shaped_values(rewritten, root);
    let hoisted = hoist_leading_subcommand(&attached, root);
    // The expansion runs **first**: it is the pass that knows a `--help=<bool>`
    // token can be another flag's value, so by the time the refusal walks the
    // result, `frpc -hc --help=false status` still has a token after the cluster
    // and is left alone (measured: Go prints **`status`'s** help with rc 0 —
    // 627 B — and the base head agreed at 1604 B), while `frpc -hc` is last after
    // the hoist and is the argv pflag refuses.
    let expanded = expand_help_bool_value_form(hoisted, root);
    reject_pflag_shorthand_cluster_that_needs_a_value(&expanded, root);
    expanded
}

/// Which binary's **root command** a cobra-shaped pre-parse pass is emulating.
///
/// Go's two root commands differ in the two facts `Find`/`stripFlags` read, so
/// neither can be described by a single shared constant:
///
/// * which child commands exist ([`RootCommand::subcommands`]);
/// * which root flags pflag registers as **bools**
///   ([`RootCommand::bool_root_flags`]) — a bool carries `NoOptDefVal =
///   "true"`, so `stripFlags` does *not* let it swallow the next argv token,
///   while every other flag does.
///
/// `frps` was previously modelled as having neither, on the stated grounds that
/// it declares no subcommands. That premise is false: `frps` declares `verify`
/// and inherits cobra's `completion`/`help` (measured — `frps --help` lists all
/// three), and it runs the same `stripFlags`-then-`Find` resolution, which is
/// where Go's measured `unknown command "true" for "frps"` for
/// `frps --strict-config true verify -c <cfg>` comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootCommand {
    Frps,
    Frpc,
}

impl RootCommand {
    /// The child command names cobra's `Find` can resolve on this root — the
    /// **whole implemented** surface, not Go's full list (cobra's `completion`
    /// and `help` are not implemented on either binary).
    fn subcommands(self) -> &'static [&'static str] {
        match self {
            RootCommand::Frps => &FRPS_SUBCOMMANDS,
            RootCommand::Frpc => &FRPC_SUBCOMMANDS,
        }
    }

    /// The long flag names this root registers with a pflag **bool**, written
    /// in frp-rs's `_` spelling.
    ///
    /// Go's `config.WordSepNormalizeFunc` normalizes the **other** way — it
    /// rewrites every `_` in a queried name to `-`
    /// (`pkg/config/flags.go:31-36`, `strings.ReplaceAll(name, "_", "-")`),
    /// which is what makes a query spelled `--strict_config` find the flag Go
    /// registers with the underscore spelling (`cmd/frps/root.go:46`,
    /// `BoolVarP(&strictConfigMode, "strict_config", …)`) while pflag renders it
    /// hyphenated — measured on Go v0.71.0, `frps --help` and
    /// `frps verify --help` both print `--strict-config`. Both spellings resolve
    /// to that one flag, so `hasNoOptDefVal` answers for both. frp-rs's
    /// [`consumes_value`] folds the token's `-` into `_` before the lookup, which
    /// is the same membership test in the opposite direction (the exemption is a
    /// set, so up to spelling there is no difference) — see that function for the
    /// measured end-to-end parity.
    ///
    /// Every entry is measured on Go v0.71.0 (the probes are tabulated in
    /// `docs/developing.md` § CLI inputs); the *complement* is the interesting
    /// half, because a name missing here is treated as value-taking:
    ///
    /// * `frps` — `version`/`-v` and `strict_config`
    ///   (`cmd/frps/root.go:44-48`), plus the three `BoolVarP` registrations in
    ///   `pkg/config/flags.go:242,246,251` (`enable_prometheus`,
    ///   `disable_log_color`, `tls_only`). Measured:
    ///   `frps --enable-prometheus verify -c <cfg>`,
    ///   `frps --disable-log-color verify -c <cfg>` and
    ///   `frps --tls-only verify -c <cfg>` all resolve the `verify` command
    ///   (rc 0), so neither flag consumed it.
    /// * `frps`'s `--dashboard-tls-mode` is **not** here, and the measurement
    ///   is why: it is registered with `VarP(BoolFuncFlag{…})`
    ///   (`pkg/config/flags.go:256-258`), not `BoolVarP`, so pflag never sets
    ///   `NoOptDefVal` on it. Measured: `frps --dashboard-tls-mode verify -c
    ///   <valid cfg>` consumes `verify` as the flag's value, finds no bare word
    ///   and **starts the server** instead of verifying (bounded and killed by
    ///   the probe's watchdog, rc 143 — the `timeout`-based rows elsewhere in
    ///   this repo report 124 for that shape).
    /// * `frpc` — `version`/`-v` and `strict_config`
    ///   (`cmd/frpc/sub/root.go:52-53`).
    fn bool_root_flags(self) -> &'static [&'static str] {
        match self {
            RootCommand::Frps => &FRPS_BOOL_ROOT_FLAGS,
            RootCommand::Frpc => &FRPC_BOOL_ROOT_FLAGS,
        }
    }
}

/// The `frpc` subcommand names [`hoist_leading_subcommand`] recognises, in the
/// order [`frpc_parser`] composes them.
///
/// This is the **whole** implemented surface: Go's `frpc --help` also lists
/// `nathole` (not implemented in frp-rs) and the cobra built-ins `completion`
/// and `help`, so `frpc -c cfg.toml nathole` stays a leftover-token refusal
/// here. The set is not hand-trusted: `every_known_subcommand_name_selects_its_own_branch`
/// runs each name through `frpc_parser` and fails on a name with no command (or
/// one that selects a different branch), and
/// `the_known_subcommand_list_is_exactly_the_parser_branches` fails when the
/// list and the parser disagree in the other direction too.
const FRPC_SUBCOMMANDS: [&str; 12] = [
    "tcp", "udp", "http", "https", "stcp", "xtcp", "sudp", "tcpmux", "verify", "reload", "status",
    "stop",
];

/// The `frps` subcommand names [`hoist_leading_subcommand`] recognises.
///
/// One name, because `verify` is the only `frps` child frp-rs implements; Go's
/// `frps --help` additionally lists the cobra built-ins `completion` and `help`
/// (measured), which stay refusals here exactly as they do on `frpc`.
/// `the_frps_command_list_is_exactly_the_parser_branches` pins this list against
/// the parser's own branches in both directions, so a name without a command
/// (or a command missing from the list) fails.
const FRPS_SUBCOMMANDS: [&str; 1] = ["verify"];

/// The pflag **bool** long flags of Go's `frps` root command, normalized to `_`.
/// See [`RootCommand::bool_root_flags`] for the source lines and the probes.
const FRPS_BOOL_ROOT_FLAGS: [&str; 5] = [
    "version",
    "strict_config",
    "enable_prometheus",
    "disable_log_color",
    "tls_only",
];

/// The pflag **bool** long flags of Go's `frpc` root command, normalized to `_`.
/// See [`RootCommand::bool_root_flags`].
const FRPC_BOOL_ROOT_FLAGS: [&str; 2] = ["version", "strict_config"];

/// Whether `token` names one of the commands `root` registers.
///
/// `s` is a whole argv token, never a prefix: cobra's `findNext`
/// (`cobra-1.8.0/command.go`) compares with `commandNameMatches`, i.e. string
/// equality (`EnablePrefixMatching` is off — frp does not set it), and frp-rs
/// does not implement prefix matching either.
fn is_known_subcommand(s: &str, root: RootCommand) -> bool {
    root.subcommands().contains(&s)
}

/// Whether cobra's `stripFlags` would treat this token as a flag that swallows
/// the next argv token — `cobra-1.8.0/command.go`, verbatim in effect: a
/// `--long` without `=` whose flag carries no `NoOptDefVal`, or a
/// two-character short flag without `=`.
///
/// The exemption list is therefore **exactly the root flags that Go registers
/// with a pflag bool**, because a pflag bool sets `NoOptDefVal =
/// "true"` (`pflag-1.0.5/bool.go:56`, reached from `BoolVarP`) — but the list is
/// **per root command**: [`RootCommand::bool_root_flags`] carries the two sets
/// with their `file:line` sources and the probes that pin them, and `frps`'s is
/// the longer one (five names against `frpc`'s two) because Go hangs the whole
/// server flag surface off `frps`'s root
/// (`config.RegisterServerConfigFlags(rootCmd, &serverCfg)`,
/// `cmd/frps/root.go:50`).
///
/// Both spellings of a bool are exempt because
/// `rootCmd.SetGlobalNormalizationFunc(config.WordSepNormalizeFunc)` makes pflag
/// resolve `--strict-config` to the same `strict_config` entry.
///
/// Everything else consumes the next token: the value-taking root flags
/// (`--config`/`-c`, `--config_dir`, `--allow-unsafe`,
/// `cmd/frpc/sub/root.go:50-51,55`; `--bind_port`/`-p`, `--token`/`-t`,
/// `--allow-ports`, `--dashboard-port`, `--log-file`, …,
/// `pkg/config/flags.go:229-255`) **and any flag cobra does not know**, because
/// `hasNoOptDefVal` returns false for a name that is not in the set — measured,
/// `frpc -x status` and `frpc --nodash status` are `unknown shorthand flag` /
/// `unknown flag` on Go (so the token after the unknown flag was never a
/// candidate).
///
/// `--help`/`-h` deliberately **stays** a consumer here. pflag makes `help` a
/// bool, so the tempting reading is "it carries `NoOptDefVal` and therefore does
/// not consume" — that reading is **falsified**, and it is worth spelling out
/// because a shallow probe cannot tell the two mechanisms apart. cobra
/// registers the help flag in `execute` (`cobra-1.8.0/command.go:885`), which
/// `ExecuteC` calls *after* `Find` (`:1090`) ran `stripFlags`; the only other
/// registration site is `getCompletions` (`cobra-1.8.0/completions.go:304`),
/// reached only by the hidden `__complete` command. So at stripping time `help`
/// is an unknown flag, `hasNoOptDefVal` returns false, and it **does** consume
/// the next token. Two measurements pin the mechanism, not just the outcome:
///
/// * `frpc --help status` prints the **root** help (`Usage: frpc [flags]`,
///   listing `Available Commands`), not the `status` help a non-consuming flag
///   would select — `frpc status --help` is `Overview of all proxies status` /
///   `Usage: frpc status [flags]`;
/// * `frpc --help notacommand` is rc **0** with that same root help. A
///   non-consuming flag would leave `notacommand` as the first bare word, and
///   Go's `legacyArgs` refuses a root-level bare word (`unknown command
///   "notacommand" for "frpc"`, rc 1).
///
/// frp-rs must match both: exempting `--help` here would hoist `status` out of
/// `--help status` and print the *status* help where Go prints the root's.
/// `help_does_not_become_a_candidate` pins the decision.
///
/// Getting the list wrong is **not** harmless in either direction, which the
/// first version of this function got wrong by listing `--strict-config` as a
/// consumer: skipping a token shifts *which* token is the first bare word, so
/// over-consuming can hoist a **later** word that cobra would have refused.
/// Measured on Go v0.71.0, `frpc --strict-config true status -c cfg` is rc 1
/// `unknown command "true" for "frpc"` — `true` is the first bare word and
/// `status` is never resolved — while the over-consuming version hoisted
/// `status` and dialled the admin port (rc 0). Under-consuming is the other
/// direction of the same bug: `frpc --strict-config status -c cfg` is rc 0 and
/// dials on Go, because `status` was not consumed. The `frps` rows are the same
/// shape and are measured in `docs/developing.md` § CLI inputs:
/// `frps --tls-only verify -c <valid cfg>` resolves `verify` (rc 0), so
/// `--tls-only` must **not** consume, while
/// `frps --dashboard-tls-mode verify -c <valid cfg>` consumes `verify` as the
/// flag's value and starts the server (bounded and killed by the probe's watchdog, rc 143), so that
/// one must.
fn consumes_value(s: &OsStr, root: RootCommand) -> bool {
    let Some(s) = s.to_str() else { return false };
    if s.contains('=') {
        return false;
    }
    match s.as_bytes() {
        [b'-', b'-', rest @ ..] if !rest.is_empty() => {
            // Go's `WordSepNormalizeFunc` rewrites `_` to `-` before the pflag
            // lookup (`pkg/config/flags.go:31-36`), so `--strict_config` and
            // `--strict-config` are one flag; folding the token the other way
            // (`-` to `_`) is the same membership test against this set.
            let name = String::from_utf8_lossy(rest).replace('-', "_");
            !root.bool_root_flags().contains(&name.as_str())
        }
        [b'-', c] => *c != b'v',
        _ => false,
    }
}

/// Move a **leading** subcommand token to the front of the argv, the way cobra
/// resolves a command that follows leading root flags (`TODO.md:4710`).
///
/// [`RootCommand`] selects which root command's flag and command sets are
/// emulated; both binaries run the same resolution, because Go's `frps` declares
/// a child command too (`verify`).
///
/// Go's `Find` (`cobra-1.8.0/command.go`, `ExecuteC` → `Find` → `innerfind`)
/// strips flags from argv with `stripFlags` and then looks at **only the first
/// surviving bare word**: if that word names a child command the child is
/// selected and `argsMinusFirstX` removes it, so the rest of argv reaches the
/// child's `pflag` parse; if it does not name a child, the root command runs
/// with the whole argv (and its positional check refuses the word). bpaf instead
/// picks a branch *before* dispatch, so with `-c pA.toml status` the run-mode
/// parser sees the `status` token as a leftover positional. Hoisting the token
/// reproduces cobra's resolution at the one point where frp-rs picks its branch.
///
/// `argv` is the argv **after** `argv[0]` was dropped and after
/// [`rewrite_config_dash_values`]; see [`prepared_cli_argv`] for why that order
/// is load-bearing.
///
/// **What counts as a candidate — measured on Go v0.71.0, not inferred.** The
/// scan skips the value of every value-taking token (see [`consumes_value`]),
/// stops at a real `--` separator, and stops at anything it cannot classify.
/// The value-position shapes this must never hoist out of, each measured on Go
/// v0.71.0 and on the frp-rs binaries (the table with both columns is in
/// `docs/developing.md` § CLI inputs):
///
/// * `-c status` — a config file literally named `status`: `status` is `-c`'s
///   value, so Go loads it **in run mode** and starts the client (measured:
///   `start frpc service for config file […]/status`), never the `status`
///   admin command. Nothing may be hoisted here.
/// * `--config=status` and `-c=status` — the `=`-attached spelling holds the
///   value inside one token; there is no next token to consume and nothing to
///   hoist.
/// * `-c cfg.toml -- status` — a real `--`; Go treats `status` as a positional
///   and runs the root command's run mode (measured: it starts the client and
///   never dials `[webServer].port`). The scan stops at `--`, so nothing after
///   it is hoisted.
/// * `-c -status` — the value is the dash-shaped token `-status` (Go:
///   `open -status: no such file or directory`); the rewrite has already
///   attached the flag-shaped spellings (`-c --strict-config=false` becomes
///   `-c=--strict-config=false`) before this runs, and a bare `-status` is
///   consumed by the same one-token lookahead.
/// * `tcp --proxy-name status` — the subcommand already leads, so no token is
///   hoisted; the value `status` belongs to the already-selected proxy command.
/// * `--strict-config true status` — the trap the **first** version of the
///   classification fell into. `--strict-config` is a pflag bool
///   (`cmd/frpc/sub/root.go:53`), so cobra does not let it swallow `true`;
///   `true` is the first bare word, and Go refuses that word
///   (`unknown command "true" for "frpc"`, rc 1) instead of resolving the
///   `status` that follows it. Treating the flag as value-taking hoisted
///   `status` and dialled the admin port (rc 0) — a regression against Go and
///   against the base. See [`consumes_value`] for the full exemption list.
/// * `--strict-config status` — the other direction, and the reason the flag
///   is exempt: `status` is not consumed, so Go resolves the command and dials
///   the config's admin port (rc 0). The same holds for the underscore
///   spelling and for `-c cfg.toml --strict_config status`.
/// * `frpc -c cfg.toml notacommand` — the first bare word is not a command and
///   Go refuses **that** word (`unknown command "notacommand" for "frpc"`,
///   rc 1), even when a real command name follows it (measured:
///   `notacommand status` is the same refusal). The first bare word is
///   therefore the only candidate; a later word is never hoisted.
///
/// The `frps` rows, each measured on Go v0.71.0 with a fresh valid config
/// (`docs/developing.md` § CLI inputs has the table):
///
/// * `frps verify -c cfg.toml` — already leading, nothing to hoist (rc 0).
/// * `frps -c cfg.toml verify` — `-c` consumes its value, so `verify` is the
///   first bare word and cobra resolves it: Go runs `verifyCmd` on `cfg.toml`,
///   rc 0. Without the hoist frp-rs answered rc 1 `` `verify` is not expected
///   in this context `` — a *valid* config reported as a failure by the one
///   command whose job is to say whether it is valid.
/// * `frps --strict-config=false verify -c cfg.toml` — an `=`-attached flag
///   never consumes, so `verify` is again the first bare word; Go rc 0
///   (lenient), and the hoist is what makes the lenient spelling reach the
///   verify branch at all.
/// * `frps --tls-only verify -c cfg.toml` — `--tls-only` is a pflag bool
///   (`pkg/config/flags.go:251`), so it does **not** swallow `verify`; Go
///   resolves the command, rc 0.
/// * `frps --dashboard-tls-mode verify -c cfg.toml` — the same shape with a
///   flag that is *not* a pflag bool (`VarP(BoolFuncFlag{…})`,
///   `pkg/config/flags.go:256-258`): `verify` becomes the flag's **value**, no
///   bare word survives, and Go runs the root command instead — measured, it
///   starts the server (`frps started successfully`, killed by the 6 s probe watchdog at rc 143). The
///   exemption list must therefore leave this name consuming.
/// * `frps --strict-config true verify -c cfg.toml` — the space form: pflag's
///   bool does not consume `true`, `true` is the first bare word, and Go
///   refuses it (`unknown command "true" for "frps"`, rc 1) rather than
///   resolving the `verify` that follows. The first bare word is the only
///   candidate on `frps` too.
///
/// Returns `argv` unchanged when there is nothing to hoist.
fn hoist_leading_subcommand(argv: &[OsString], root: RootCommand) -> Vec<OsString> {
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        if arg == "--" {
            // A real end-of-flags marker: every later token is a positional and
            // cobra's `stripFlags` returns before looking at them.
            return argv.to_vec();
        }
        if arg.to_string_lossy().starts_with('-') {
            // A flag — never a candidate. A value-taking flag also swallows the
            // token after it, which is how `-c status` keeps its value.
            i += if consumes_value(arg, root) { 2 } else { 1 };
            continue;
        }
        let Some(word) = arg.to_str() else {
            // Not valid UTF-8, so not a subcommand name; the first bare word has
            // been seen and cobra would not look further.
            return argv.to_vec();
        };
        if is_known_subcommand(word, root) && i > 0 {
            let mut out = Vec::with_capacity(argv.len());
            out.push(arg.clone());
            out.extend(argv[..i].iter().cloned());
            out.extend(argv[i + 1..].iter().cloned());
            return out;
        }
        return argv.to_vec();
    }
    argv.to_vec()
}

/// Parse frps CLI args. Prints help/version and exits as needed.
pub fn parse_frps_args() -> FrpsCmd {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let (name, rest) = cli_args(&argv);
    // Go's pflag consumes a `-`-prefixed token as a config flag's value on
    // `frps` too; bpaf only refuses the tokens it classifies as flags (see
    // [`rewrite_config_dash_values`]). Shared with `frpc` through
    // [`prepared_cli_argv`] — measured on Go frps v0.71.0:
    // `-c --strict-config=false` and `-c -x` are
    // `open <token>: no such file or directory` there, and `-c --` is
    // `open --: no such file or directory`. `warn_if_strict_config_space_form_used`
    // keeps reading the original argv. [`RootCommand::Frps`] also runs the
    // subcommand hoist, which Go has always run here: `frps -c cfg.toml verify`
    // resolves `verify` and exits 0 (measured), not the rc 1 leftover-token
    // refusal this binary used to answer with.
    let parse_argv = prepared_cli_argv(&rest, RootCommand::Frps);
    let cmd = run_cli(
        frps_parser()
            .to_options()
            .descr("frps is the server of frp-rs (https://github.com/fatedier/frp)"),
        name,
        &parse_argv,
        help_request(RootCommand::Frps, &parse_argv),
    );
    // Only reached when the argv parsed: the failure path above exits the
    // process, so the warning can never fire for a refused argv, and the
    // detection never matches the `=`, bare or non-bool forms.
    warn_if_strict_config_space_form_used(&argv);
    // `--version` is acted on **after** the parse, and only on the run path:
    // Go hangs it off `rootCmd` but prints a version only in the root command's
    // `RunE` (`cmd/frps/root.go:57-60`), so `frps verify --version -c <valid>`
    // verifies (rc 0, `syntax is ok`) instead of printing a version — measured,
    // and pinned by `frps/tests/cli_exit_codes.rs`.
    if let FrpsCmd::Run(args) = &cmd {
        if args.show_version {
            println!("frps {} (Rust)", crate::VERSION);
            std::process::exit(0);
        }
    }
    cmd
}

// ──────────────────────────────────────────────────────────────────────
// frpc CLI — run mode + 12 subcommands: tcp, udp, http, https, stcp, xtcp,
// sudp, tcpmux, verify, reload, status, stop. Go frp v0.71.0's `frpc --help`
// lists those 12 plus `nathole` (not implemented here), `completion` and
// `help` (cobra built-ins).
// ──────────────────────────────────────────────────────────────────────

/// CLI arguments for frpc (client).
#[derive(Debug, Clone)]
pub enum FrpcCmd {
    /// Normal mode: load config file and run all proxies
    Run(FrpcRunArgs),
    /// Single TCP proxy (no config file)
    Tcp(TcpArgs),
    /// Single UDP proxy
    Udp(UdpArgs),
    /// Single HTTP proxy
    Http(HttpArgs),
    /// Single HTTPS proxy
    Https(HttpsArgs),
    /// Single STCP proxy
    Stcp(StcpArgs),
    /// Single XTCP proxy
    Xtcp(XtcpArgs),
    /// Single SUDP proxy
    Sudp(SudpArgs),
    /// Single TCPMUX proxy
    Tcpmux(TcpmuxArgs),
    /// Verify config file
    Verify(VerifyArgs),
    /// Reload running frpc configuration via admin API
    Reload(ReloadArgs),
    /// Query running frpc proxy status via admin API
    Status(StatusArgs),
    /// Stop running frpc via admin API
    Stop(StopArgs),
}

#[derive(Debug, Clone)]
pub struct FrpcRunArgs {
    pub config: String,
    pub config_dir: Option<String>,
    pub strict_config: bool,
    pub allow_unsafe: Vec<String>,
    pub show_version: bool,
    pub log_file: Option<String>,
    pub log_level: Option<String>,
    pub log_max_days: Option<i32>,
    pub log_format: Option<String>,
    pub disable_log_color: bool,
}

#[derive(Debug, Clone)]
pub struct TcpArgs {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub proxy_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UdpArgs {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub proxy_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpArgs {
    pub local_ip: String,
    pub local_port: u16,
    pub custom_domains: String,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub subdomain: Option<String>,
    pub locations: Option<String>,
    pub http_user: Option<String>,
    pub http_pwd: Option<String>,
    pub host_header_rewrite: Option<String>,
    pub proxy_name: Option<String>,
    pub use_encryption: bool,
    pub use_compression: bool,
}

#[derive(Debug, Clone)]
pub struct HttpsArgs {
    pub local_ip: String,
    pub local_port: u16,
    pub custom_domains: String,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub subdomain: Option<String>,
    pub proxy_name: Option<String>,
    pub use_encryption: bool,
    pub use_compression: bool,
}

#[derive(Debug, Clone)]
pub struct StcpArgs {
    pub sk: String,
    pub server_name: Option<String>,
    pub local_ip: String,
    pub local_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    /// Go's `-n/--proxy-name`. frp-rs's `--tls-server-name` double-duties as the
    /// proxy name here (a pre-existing mismatch with Go, where it sets the
    /// client's TLS SNI); when both are given `--proxy-name` wins.
    pub proxy_name: Option<String>,
    pub use_encryption: bool,
    pub use_compression: bool,
}

#[derive(Debug, Clone)]
pub struct XtcpArgs {
    pub sk: String,
    pub server_name: Option<String>,
    pub local_ip: String,
    pub local_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    /// See [`StcpArgs::proxy_name`].
    pub proxy_name: Option<String>,
    pub use_encryption: bool,
    pub use_compression: bool,
}

#[derive(Debug, Clone)]
pub struct SudpArgs {
    pub local_ip: String,
    pub local_port: u16,
    /// frp-rs extension: Go's `frpc sudp` registers **no** `remote_port` at all
    /// (and, measured on the v0.71.0 binary, refuses both `-r` and
    /// `--remote-port`). The long form predates this branch and stays for
    /// command lines written against it; it carries no `-r` shorthand, so it can
    /// never be mistaken for Go's row.
    pub remote_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    /// Go's `--sk` on this surface (`ProxyConfig::sk`, honoured by the server's
    /// visitor sign-key path). Optional like Go's, which defaults it to "".
    pub sk: Option<String>,
    pub proxy_name: Option<String>,
    pub use_encryption: bool,
    pub use_compression: bool,
}

#[derive(Debug, Clone)]
pub struct TcpmuxArgs {
    pub local_ip: String,
    pub local_port: u16,
    /// frp-rs extension: a port the tcpmux path never used (the server routes by
    /// domain and reads `multiplexer`, not this). Defaults to 0 when omitted.
    pub mux_port: u16,
    /// Go's `--mux string`: the multiplexer name. `None` means Go's default
    /// (`httpconnect`), which is all frp-rs's server implements.
    pub mux: Option<String>,
    /// Go's `-d/--custom-domain strings` on this surface, comma-joined like the
    /// http/https surfaces (Go's StringSlice, narrowed to the same grammar).
    pub custom_domains: Option<String>,
    /// Go's `--sd`.
    pub subdomain: Option<String>,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub proxy_name: Option<String>,
    pub use_encryption: bool,
    pub use_compression: bool,
}

#[derive(Debug, Clone)]
pub struct VerifyArgs {
    /// The config path to verify. **Empty** on `frps` when `-c` was absent:
    /// Go's frps registers `-c` with an empty default and `verifyCmd` answers
    /// that with `frps: the configuration file is not specified` + rc 0
    /// (`cmd/frps/verify.go:36-39`). On `frpc` the flag is required and this is
    /// never empty (`cmd/frpc/sub/root.go` defaults `cfgFile` to `./frpc.ini`,
    /// a default frp-rs's `frpc verify` deliberately does not take).
    pub config: String,
    /// Go frp v0.71.0: `strict_config` is a persistent rootCmd flag on **both**
    /// binaries (`cmd/frpc/sub/root.go`, `cmd/frps/root.go:46`), so
    /// `frpc verify` and `frps verify` honor it too — each verify command
    /// passes the flag to its config loader (`cmd/frpc/sub/verify.go:37`,
    /// `cmd/frps/verify.go:40`).
    pub strict_config: bool,
    /// The `--allow-unsafe` allow-list, **read** on both verify commands (see
    /// [`allow_unsafe_parser`]).
    ///
    /// Go's verify path consults it because the gate lives inside the
    /// validation the loaded config goes through: measured on Go v0.71.0,
    /// `frps verify -c <exec tokenSource cfg>` is rc 1 with stdout
    /// `unsafe feature "TokenSourceExec" is not enabled. …` and rc 0 with
    /// `--allow-unsafe TokenSourceExec` (identical for `frpc verify`). frp-rs's
    /// load path runs the same predicate from
    /// [`crate::config::load_server_config_checked`] /
    /// [`crate::config::load_client_config_with_presence_checked`], so the
    /// value has to reach `run_verify` — dropping it here is what made `verify`
    /// accept a config the daemon refuses.
    pub allow_unsafe: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReloadArgs {
    pub config: Option<String>,
    pub strict_config: bool,
    pub admin_addr: Option<String>,
    pub admin_port: Option<u16>,
    pub admin_user: Option<String>,
    pub admin_pwd: Option<String>,
    /// Deadline for the whole admin HTTP call; default
    /// [`DEFAULT_ADMIN_API_TIMEOUT`] (Go's `adminAPITimeout`).
    pub api_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct StatusArgs {
    pub config: Option<String>,
    /// Go frp v0.71.0: `--strict-config` is a persistent rootCmd flag
    /// (cmd/frpc/sub/root.go), so `frpc status` accepts it too — and
    /// `NewAdminCommand` passes it to `config.LoadClientConfig`
    /// (cmd/frpc/sub/admin.go:57). Absent → true.
    pub strict_config: bool,
    pub json: bool,
    pub admin_addr: Option<String>,
    pub admin_port: Option<u16>,
    pub admin_user: Option<String>,
    pub admin_pwd: Option<String>,
    /// Deadline for the whole admin HTTP call; default
    /// [`DEFAULT_ADMIN_API_TIMEOUT`] (Go's `adminAPITimeout`).
    pub api_timeout: Duration,
}

/// Arguments of `frpc stop` — [`StatusArgs`] without `--json`, mirroring Go's
/// registration (all three admin commands get the same flag set).
#[derive(Debug, Clone)]
pub struct StopArgs {
    pub config: Option<String>,
    /// Go frp v0.71.0: `--strict-config` is a persistent rootCmd flag
    /// (cmd/frpc/sub/root.go), so `frpc stop` accepts it too — and
    /// `NewAdminCommand` passes it to `config.LoadClientConfig`
    /// (cmd/frpc/sub/admin.go:57). Absent → true.
    pub strict_config: bool,
    pub admin_addr: Option<String>,
    pub admin_port: Option<u16>,
    pub admin_user: Option<String>,
    pub admin_pwd: Option<String>,
    /// Deadline for the whole admin HTTP call; default
    /// [`DEFAULT_ADMIN_API_TIMEOUT`] (Go's `adminAPITimeout`).
    pub api_timeout: Duration,
}

// ─── frpc parser combinators ─────────────────────────────────────────

/// `-c`/`--config`, matching Go's pflag `StringVar`: a repeated flag is
/// **last-wins** and never an error.
///
/// Go registers `-c` with `StringVarP` inside `func init()`
/// (`cmd/frpc/sub/root.go`), so `frpc status -c a.toml -c b.toml` parses `a`
/// first and overwrites it with `b`. Measured on Go v0.71.0 darwin/arm64 with
/// `noweb.toml` (no `[webServer]`) followed by `p7499.toml`
/// (`[webServer] port = 7499`): `frpc status -c noweb.toml -c p7499.toml` dials
/// `127.0.0.1:7499` (rc 1, `connect: connection refused`) — the first config's
/// port-less refusal is never reached. The reverse order
/// (`-c p7499.toml -c noweb.toml`) prints
/// `web server port should be set if you want to use this feature`.
///
/// bpaf exits with `argument \`-c\` cannot be used multiple times in this
/// context` on the second occurrence, so every parser that takes a config
/// path wraps the argument in [`Parser::last`] (bpaf's documented
/// contradicting-options combinator: run the inner parser as many times as it
/// succeeds and return the last value). `.last()` fails when the flag is
/// absent, exactly like the bare `argument` it replaces, so a required `-c`
/// stays required and an `.optional()`/`.fallback()` wrapper keeps its previous
/// meaning. The **`frps` run path** is deliberately not one of these: its `-c`
/// stays bpaf's duplicate refusal, the pre-existing divergence from pflag
/// last-wins recorded in `docs/developing.md` § CLI inputs, and this change
/// does not touch it (`svr_config`). The `frps verify` subcommand **is** one of
/// them, because Go's `verifyCmd` reads that same persistent pflag and is
/// therefore last-wins like the `frpc` parsers.
fn config_arg() -> impl Parser<String> {
    long("config").short('c').argument::<String>("FILE").last()
}

// ─── The persistent rootCmd flags every subcommand parses ────────────

/// `--config-dir`, as an ignored persistent root flag. Same spellings as the
/// run-mode flag (hyphen plus the frp-rs underscore alias) and Go's pflag
/// semantics: last-wins on repetition.
fn ignored_config_dir() -> impl Parser<Option<String>> {
    long("config-dir")
        .long("config_dir")
        .argument::<String>("DIR")
        .last()
        .optional()
}

/// Go's `encoding/csv` message for a quote that is never closed, or for a
/// non-delimiter after a closing quote. Both are `ErrQuote` in Go, and both are
/// refused by pflag's `strings` value.
const CSV_MISSING_QUOTE: &str = "extraneous or missing \" in quoted-field";

/// Go's `encoding/csv` message for a `"` that appears inside an unquoted field.
const CSV_BARE_QUOTE: &str = "bare \" in non-quoted-field";

/// One `--allow-unsafe` occurrence, split the way pflag's `strings` value does.
///
/// Go registers the flag as `StringSliceVarP` (frpc `cmd/frpc/sub/root.go:55`,
/// frps `cmd/frps/root.go:47`), and pflag reads a `strings` value with its
/// `readAsCSV` helper: Go's `encoding/csv` reader with `LazyQuotes=false` and
/// `TrimLeadingSpace=false`, reading **one record**. So the value is CSV —
/// matched quotes are stripped, whitespace is **not** trimmed, leading blank
/// lines are skipped, and a malformed record is a flag error. Exactly one
/// record is read: its terminator ends the read, and the rest of the value is
/// never parsed.
///
/// Measured on Go v0.71.0 with `frpc verify -c <exec tokenSource cfg>
/// --allow-unsafe <value>` (rc 0 means the value enabled `TokenSourceExec`;
/// rc 1 with an `invalid argument … for "--allow-unsafe" flag` line on stderr
/// means pflag refused it; rc 1 with the `unsafe feature … is not enabled` gate
/// line means it parsed but did not carry the feature):
///
/// | value | pflag reads | rc |
/// |---|---|---|
/// | `"TokenSourceExec"` | `TokenSourceExec` (matched quotes stripped) | 0 |
/// | `A, TokenSourceExec` | `A`, ` TokenSourceExec` (space kept) | 1 |
/// | `TokenSourceExec` | `TokenSourceExec` | 0 |
/// | `Ignored,TokenSourceExec` | `Ignored`, `TokenSourceExec` | 0 |
/// | `"a""b"` (doubled quote inside a field) | `a"b` | 1 |
/// | `"a,b"` (comma inside quotes) | `a,b` | 1 |
/// | `a,,b` (empty element) | `a`, ``, `b` | 1 |
/// | `"a""b",TokenSourceExec`, `"a,b",TokenSourceExec`, `a,,b,TokenSourceExec` | those fields plus `TokenSourceExec` | 0 |
/// | `TokenSourceExec\r` | `TokenSourceExec` (trailing CR is a terminator) | 0 |
/// | `"abc` (unclosed quote) | error `extraneous or missing " in quoted-field` | 1 |
/// | `a"b` (bare quote) | error `bare " in non-quoted-field` | 1 |
/// | `"TokenSourceExec"x` (junk after the quote) | error `extraneous or missing "` | 1 |
/// | `"TokenSourceExec"\njunk` | `TokenSourceExec` (later records never read) | 0 |
/// | `\nTokenSourceExec` | `TokenSourceExec` (leading blank lines are skipped) | 0 |
/// | `\n`, `\r\n`, `\r` | error `EOF` (a blank-only value is a flag error) | 1 |
/// | `\n"a` | error `parse error on line 2, column 3: …` (blank line skipped) | 1 |
/// | ` TokenSourceExec`, `'TokenSourceExec'`, `A,\tTokenSourceExec` | kept verbatim | 1 |
///
/// The empty value is pflag's `readAsCSV("")` special case and yields no
/// features rather than one empty one. Error wording is frp-rs's, shaped after
/// Go's `encoding/csv` `ParseError`: a 1-based **byte** column on a 1-based
/// line, with Go's `record on line N; ` prefix when the record started on an
/// earlier line than the error (a quoted field may span lines). What is pinned
/// is the refusal and those numbers, not the sentence around them.
fn split_allow_unsafe_csv(value: &str) -> Result<Vec<String>, String> {
    // pflag's `readAsCSV` returns an empty slice, not `[""]`, for "".
    if value.is_empty() {
        return Ok(Vec::new());
    }
    read_csv_record(value)
}

/// Go's `encoding/csv` `Reader.Read` for one record, with `Comma=','`,
/// `LazyQuotes=false` and `TrimLeadingSpace=false` — the configuration pflag's
/// `readAsCSV` uses. Mirrors `readRecord`/`readLine` from Go 1.27.1's
/// `$GOROOT/src/encoding/csv/reader.go`: blank lines before the record are skipped, a
/// quoted field may span lines, and errors carry Go's `ParseError` numbers.
fn read_csv_record(value: &str) -> Result<Vec<String>, String> {
    // Go's `readLine` normalises `\r\n` to `\n` on every line and drops a
    // trailing `\r` at end of input; both are properties of the byte stream, so
    // they are applied once here and `CsvReader::read_line` stays a plain split.
    let normalized = normalize_csv_input(value);
    let mut reader = CsvReader::new(&normalized);
    // Read the first non-blank line (Go's `readRecord` skip loop; comments are
    // off for pflag's reader, so only the empty-line arm applies).
    let (mut line, eof) = loop {
        let (line, eof) = reader.read_line();
        if !eof && line.len() == length_nl(line) {
            continue;
        }
        break (line, eof);
    };
    // Blank lines only: Go's reader returns `io.EOF`, which pflag reports as
    // `invalid argument … for "--allow-unsafe" flag: EOF`.
    if eof {
        return Err("EOF".to_string());
    }
    let start_line = reader.line;
    let mut record: Vec<u8> = Vec::new();
    let mut fields: Vec<Vec<u8>> = Vec::new();
    let mut pos_line = reader.line;
    let mut pos_col = 1usize;
    'parse_field: loop {
        if line.is_empty() || line[0] != b'"' {
            // Non-quoted field: up to the next comma, or to the end of the line
            // with the terminator removed.
            let comma = line.iter().position(|&b| b == b',');
            let end = comma.unwrap_or_else(|| line.len() - length_nl(line));
            let field = &line[..end];
            if let Some(j) = field.iter().position(|&b| b == b'"') {
                return Err(csv_error(
                    start_line,
                    reader.line,
                    pos_col + j,
                    CSV_BARE_QUOTE,
                ));
            }
            record.extend_from_slice(field);
            fields.push(std::mem::take(&mut record));
            if let Some(i) = comma {
                line = &line[i + 1..];
                pos_col += i + 1;
                continue 'parse_field;
            }
            break 'parse_field;
        }
        // Quoted field: the opening quote is not part of the value.
        line = &line[1..];
        pos_col += 1;
        loop {
            if let Some(i) = line.iter().position(|&b| b == b'"') {
                record.extend_from_slice(&line[..i]);
                line = &line[i + 1..];
                pos_col += i + 1;
                match line.first() {
                    // `""` sequence: one literal quote.
                    Some(b'"') => {
                        record.push(b'"');
                        line = &line[1..];
                        pos_col += 1;
                    }
                    // `",` sequence: end of field.
                    Some(b',') => {
                        line = &line[1..];
                        pos_col += 1;
                        fields.push(std::mem::take(&mut record));
                        continue 'parse_field;
                    }
                    // The closing quote at the end of a line, or of the input,
                    // ends both the field and the record.
                    _ if length_nl(line) == line.len() => {
                        fields.push(std::mem::take(&mut record));
                        break 'parse_field;
                    }
                    // An invalid, non-escaped quote. Go reports `ErrQuote` at
                    // the closing quote's own byte column, not at the offending
                    // rune's (measured: `"TokenSourceExec"x` is column 17, not
                    // 18).
                    _ => {
                        return Err(csv_error(
                            start_line,
                            pos_line,
                            pos_col - 1,
                            CSV_MISSING_QUOTE,
                        ))
                    }
                }
            } else if !line.is_empty() {
                // Hit the end of the line inside a quoted field: the newline is
                // data. Go's `if errRead != nil` arm here is a non-EOF read
                // error, which a `&str` cannot produce.
                record.extend_from_slice(line);
                pos_col += line.len();
                let (next, _) = reader.read_line();
                line = next;
                if !line.is_empty() {
                    pos_line += 1;
                    pos_col = 1;
                }
            } else {
                // Abrupt end of input inside a quoted field. Go has already
                // cleared `readLine`'s `io.EOF` here, so the unterminated quote
                // is always reported at the current position.
                return Err(csv_error(start_line, pos_line, pos_col, CSV_MISSING_QUOTE));
            }
        }
    }
    Ok(fields
        .into_iter()
        .map(|field| String::from_utf8_lossy(&field).into_owned())
        .collect())
}

/// Go's `encoding/csv` input normalisation, applied once so the reader can work
/// on plain `\n`-separated lines: every `\r\n` becomes `\n` (Go's `readLine`
/// rewrites the byte rather than dropping it), and a trailing `\r` with no
/// `\n` after it is dropped ("for backwards compatibility", Go's `readLine`).
/// A `\r` anywhere else is data.
fn normalize_csv_input(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            if i + 1 == bytes.len() {
                // Drop the trailing \r before end of input.
                break;
            }
            if bytes[i + 1] == b'\n' {
                out.push(b'\n');
                i += 2;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// The byte count of a line's trailing `\n`, Go's `lengthNL`.
fn length_nl(line: &[u8]) -> usize {
    usize::from(line.last() == Some(&b'\n'))
}

/// One record's worth of Go's `encoding/csv` input state: the bytes, the
/// current byte offset, and the 1-based number of the last line read.
struct CsvReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    /// Go's `Reader.numLine`.
    line: usize,
}

impl<'a> CsvReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        CsvReader {
            bytes,
            offset: 0,
            line: 0,
        }
    }

    /// Go's `readLine` on already-normalised input: the next line *with* its
    /// `\n` terminator. The bool is Go's `err == io.EOF` — true only when no
    /// bytes were left at all.
    fn read_line(&mut self) -> (&'a [u8], bool) {
        let start = self.offset;
        let mut end = start;
        while end < self.bytes.len() && self.bytes[end] != b'\n' {
            end += 1;
        }
        let had_newline = end < self.bytes.len();
        let raw = &self.bytes[start..if had_newline { end + 1 } else { end }];
        self.offset = start + raw.len();
        self.line += 1;
        (raw, raw.is_empty())
    }
}

/// Go's `encoding/csv` `ParseError.Error` shape: a 1-based byte column on a
/// 1-based line, with the `record on line N; ` prefix when the record started
/// on an earlier line than the error (a quoted field may span lines).
fn csv_error(start_line: usize, line: usize, column: usize, reason: &str) -> String {
    if start_line == line {
        format!("parse error on line {line}, column {column}: {reason}")
    } else {
        format!(
            "record on line {start_line}; parse error on line {line}, column {column}: {reason}"
        )
    }
}

/// Every `--allow-unsafe` occurrence, read in order through
/// [`split_allow_unsafe_csv`] — pflag's `strings` value appends per occurrence.
fn allow_unsafe_values(values: Vec<String>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for value in values {
        out.extend(split_allow_unsafe_csv(&value)?);
    }
    Ok(out)
}

/// `--allow-unsafe`, **read** rather than ignored: Go registers it as a pflag
/// `strings` (CSV, repeatable), and the value feeds
/// [`UnsafeFeatures`](crate::unsafe_features::UnsafeFeatures) on the run paths
/// and on both `verify` commands (Go's own `verify` consults the same persistent
/// flag through `ValidateServerConfig`/`ValidateClientConfig`: measured on
/// v0.71.0, `frps verify -c <exec cfg>` is rc 1 without it and rc 0 with
/// `--allow-unsafe TokenSourceExec`).
///
/// pflag's `strings` value **appends** on repetition and reads every occurrence
/// through [`split_allow_unsafe_csv`], so the parser is `.many()` plus a
/// flatten. Measured on v0.71.0: `frps verify -c <exec cfg> --allow-unsafe
/// WrongFeature --allow-unsafe TokenSourceExec` and the same argv with the two
/// values swapped are both rc 0 (and `--allow-unsafe Ignored,TokenSourceExec`
/// is rc 0), i.e. an unrelated value in any position does not cancel the
/// enabling one. Without `.many()` bpaf refuses the second occurrence with
/// ``argument `--allow-unsafe` cannot be used multiple times in this context``
/// — rc 1 on `frps verify`, `frpc verify` and `frpc -c` alike, which is the
/// divergence the repeated-flag rows of `frps/tests/cli_exit_codes.rs` and
/// `frpc/tests/cli_exit_codes.rs` pin.
fn allow_unsafe_parser() -> impl Parser<Vec<String>> {
    long("allow-unsafe")
        .long("allow_unsafe")
        .argument::<String>("FEATURES")
        .many()
        .parse(allow_unsafe_values)
        .fallback(vec![])
}

/// `--allow-unsafe`, as an ignored persistent root flag. Same spellings as the
/// run-mode flag (hyphen plus the frp-rs underscore alias) and the same pflag
/// `strings` grammar ([`split_allow_unsafe_csv`]): repeats append, each
/// occurrence is read as one CSV record, and a malformed one is a flag error.
///
/// Go parses this persistent flag for **every** subcommand, so the ignored
/// surface must refuse what pflag refuses even though frp-rs drops the value:
/// measured on v0.71.0, `frpc tcp|status|reload -c <cfg> --allow-unsafe '"abc'`
/// is rc 1 `Error: invalid argument "\"abc" for "--allow-unsafe" flag: parse
/// error on line 1, column 5: extraneous or missing " in quoted-field`.
///
/// Only the subcommands that do not read it use this — `verify` reads
/// [`allow_unsafe_parser`] instead (Go's verify *does* consult the value).
fn ignored_allow_unsafe() -> impl Parser<Vec<String>> {
    long("allow-unsafe")
        .long("allow_unsafe")
        .argument::<String>("FEATURES")
        .many()
        .parse(allow_unsafe_values)
}

/// `-v`/`--version`, as an ignored persistent root flag. Go registers it as a
/// persistent **rootCmd bool**, and only the root command's `RunE` prints the
/// version: measured on Go v0.71.0, `frpc tcp … --version` starts the proxy
/// exactly like the same argv without it. The value grammar is the shared
/// Go-bool one, so `--version=foo` is still the pflag value error.
fn ignored_version() -> impl Parser<bool> {
    go_bool_flag!("version", None, Some('v'), "Version of frpc").last()
}

/// The persistent root flags the config-reading subcommands that do not read
/// `--allow-unsafe` (`reload`/`status`/`stop`) did not declare: `-c` and
/// `--strict-config` are already fields of their own parsers.
fn ignored_admin_root_flags() -> impl Parser<()> {
    construct!(
        ignored_config_dir(),
        ignored_allow_unsafe(),
        ignored_version()
    )
    .map(|_| ())
}

/// [`ignored_admin_root_flags`] minus `--allow-unsafe`, for `frpc verify` — the
/// one config-reading subcommand that **reads** it ([`allow_unsafe_parser`],
/// because the load-path gate consults the value). The two parsers cannot
/// coexist in one `construct!`: bpaf would have to consume the same named
/// argument twice.
fn ignored_admin_root_flags_except_allow_unsafe() -> impl Parser<()> {
    construct!(ignored_config_dir(), ignored_version()).map(|_| ())
}

/// All five persistent rootCmd flags, accepted and ignored on the eight
/// single-proxy commands.
///
/// Go registers these on `rootCmd` (`cmd/frpc/sub/root.go`, `func init()`), so
/// pflag parses them for **every** subcommand — `frpc tcp --help` lists them
/// under `Global Flags` beside the command's own flags. The single-proxy
/// commands never read any of them: measured on Go v0.71.0, every shape in
/// `docs/developing.md` § CLI inputs (including `-c missing.toml`,
/// `--config-dir cDir` and a `-`-prefixed value after `-c`) reaches
/// `try to connect to server...` and connects to the probe port exactly like
/// the same argv with the flag removed. Acceptance is the parity, not the
/// value, so all five are dropped here.
///
/// Scalar flags go through [`Parser::last`] because a repeated pflag flag is
/// last-wins and never an error — measured on Go, the proxy still starts with
/// `-c a -c b`, `--config-dir a --config-dir b`, `--strict-config
/// --strict-config=false` and `--version --version`.
fn ignored_proxy_root_flags() -> impl Parser<()> {
    let config = config_arg().optional();
    let config_dir = ignored_config_dir();
    let strict_config = strict_config_parser().last();
    let allow_unsafe = ignored_allow_unsafe();
    let version = ignored_version();
    construct!(config, config_dir, strict_config, allow_unsafe, version).map(|_| ())
}

/// Attach [`ignored_proxy_root_flags`] to one single-proxy command's own
/// argument parser and map the pair down to the command's `FrpcCmd` variant.
fn single_proxy_cmd<T, P, F>(args: P, f: F) -> impl Parser<FrpcCmd>
where
    P: Parser<T> + 'static,
    T: 'static,
    F: Fn(T) -> FrpcCmd + 'static,
{
    construct!(args, ignored_proxy_root_flags()).map(move |(args, _)| f(args))
}

/// Rewrite pflag's `-c <dash-value>` spellings into bpaf's attached
/// `-c=<dash-value>` form, before bpaf sees argv. Used by **both** binaries —
/// [`parse_frps_args`] and [`parse_frpc_args`] — because Go's `frps` shares the
/// rule through pflag, not only cobra's `frpc` subcommands.
///
/// Go's pflag consumes the **next argv token** as a value for a value-taking
/// flag with no regard for a leading `-`. bpaf classifies tokens first
/// (`split_os_argument`, `bpaf-0.9.27/src/arg.rs:118-215`, then
/// `disambiguate_short`, `bpaf-0.9.27/src/args.rs:183-250`): `--long` becomes
/// `Arg::Long`; a single-dash token becomes `Arg::Short` when it has one
/// character, when the character after the first is `=`, or when its first
/// character is a short the parser registers; and only an unknown
/// multi-character single-dash token falls back to `Arg::Word`. `State::take_arg`
/// (`bpaf-0.9.27/src/args.rs:670-694`) accepts only the `Word`/`ArgWord` items
/// that tokenisation produced, so measured at the base head: it already took
/// `-foo.toml`, `-nonexistent.toml` and `-=v` (unknown multi-character tokens
/// demoted to `Arg::Word`), and refused `--strict-config=false`, `-x`, `-c`,
/// `-a=b` and `--long`. Only for those flag-shaped tokens did
/// `-c <token>` exit with ``-c` requires an argument `FILE``.
/// Measured on Go v0.71.0: `frpc status -c --strict-config=false` alone is
/// `open --strict-config=false: no such file or directory` (the token is `-c`'s
/// value, not the flag), and `frpc status -c --strict-config=false -c
/// p7498.toml` dials the second config's port because the later `-c` overwrites
/// it. frp-rs now accepts both.
///
/// Scope is exactly the config-selecting persistent flags — `-c`, `--config`,
/// `--config-dir` and the frp-rs `--config_dir` alias — so this does not
/// generalise pflag's rule to every value-taking flag; a `-`-prefixed value for
/// any other flag is left untouched. `--config-dir`/`--config_dir` are not Go
/// `frps` flags (Go answers `unknown flag: --config-dir`, rc 1) — they are
/// frp-rs's own, and the rewrite covers their dash-valued form here so the flag
/// behaves the same on both binaries. Nothing after the first `--` is rewritten
/// (Go treats those as positional args), except that a `--` consumed as a
/// config value is attached like any other value, which is what Go does.
fn rewrite_config_dash_values(argv: &[OsString]) -> Vec<OsString> {
    const CONFIG_FLAGS: [&str; 4] = ["-c", "--config", "--config-dir", "--config_dir"];
    let mut out = Vec::with_capacity(argv.len());
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        if arg == "--" {
            out.extend(argv[i..].iter().cloned());
            break;
        }
        let attach = CONFIG_FLAGS.iter().any(|flag| arg == flag)
            && argv
                .get(i + 1)
                .is_some_and(|next| next.to_string_lossy().starts_with('-'));
        if attach {
            let mut joined = arg.clone();
            joined.push("=");
            joined.push(&argv[i + 1]);
            out.push(joined);
            i += 2;
        } else {
            out.push(arg.clone());
            i += 1;
        }
    }
    out
}

fn run_mode() -> impl Parser<FrpcRunArgs> {
    let config = config_arg().fallback("frpc.toml".into());
    let config_dir = long("config-dir")
        .long("config_dir")
        .argument::<String>("DIR")
        .optional();
    let strict_config = strict_config_parser();
    let allow_unsafe = allow_unsafe_parser();
    let show_version = go_bool_flag!("version", None, Some('v'), "Version of frpc");
    let log_file = long("log-file")
        .long("log_file")
        .argument::<String>("FILE")
        .optional();
    let log_level = long("log-level")
        .long("log_level")
        .short('L')
        .argument::<String>("LEVEL")
        .optional();
    let log_max_days = long("log-max-days")
        .long("log_max_days")
        .argument::<i32>("DAYS")
        .optional();
    let log_format = long("log-format")
        .long("log_format")
        .argument::<String>("FORMAT")
        .optional();
    let disable_log_color = go_bool_flag!(
        "disable-log-color",
        Some("disable_log_color"),
        None,
        "Disable log color in console",
    );
    construct!(FrpcRunArgs {
        config,
        config_dir,
        strict_config,
        allow_unsafe,
        show_version,
        log_file,
        log_level,
        log_max_days,
        log_format,
        disable_log_color
    })
}

// ─── Subcommand parsers (inlined — bpaf construct! doesn't support destructuring tuples from parser fns) ───

fn tcp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .short('i')
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .short('l')
        .argument::<u16>("PORT");
    let remote_port = long("remote-port")
        .long("remote_port")
        .short('r')
        .argument::<u16>("PORT");
    let server_addr = long("server-addr")
        .long("server_addr")
        .short('s')
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .short('P')
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    // Go registers this pair on every proxy surface as `--uc` ("use
    // compression") and `--ue` ("use encryption"), both pflag bools; frp-rs
    // used to spell them out and accept neither of Go's names. Go's names are
    // now the primary longs (the only ones rendered) and the old spellings are
    // hidden aliases, so both command lines parse. The value grammar is Go's —
    // measured, `frpc tcp --ue=false …` is accepted by Go and the proxy runs.
    let use_encryption = go_bool_flag_with_aliases!(
        "ue",
        &["use-encryption", "use_encryption"],
        None,
        "use encryption",
    );
    let use_compression = go_bool_flag_with_aliases!(
        "uc",
        &["use-compression", "use_compression"],
        None,
        "use compression",
    );
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .short('n')
        .argument::<String>("NAME")
        .optional();
    let args = construct!(TcpArgs {
        local_ip,
        local_port,
        remote_port,
        server_addr,
        server_port,
        token,
        use_encryption,
        use_compression,
        proxy_name,
    });
    single_proxy_cmd(args, FrpcCmd::Tcp)
        .to_options()
        .command("tcp")
        .help("Run frpc with a single tcp proxy")
}

fn udp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .short('i')
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .short('l')
        .argument::<u16>("PORT");
    let remote_port = long("remote-port")
        .long("remote_port")
        .short('r')
        .argument::<u16>("PORT");
    let server_addr = long("server-addr")
        .long("server_addr")
        .short('s')
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .short('P')
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .short('n')
        .argument::<String>("NAME")
        .optional();
    let use_encryption = go_bool_flag_with_aliases!(
        "ue",
        &["use-encryption", "use_encryption"],
        None,
        "use encryption",
    );
    let use_compression = go_bool_flag_with_aliases!(
        "uc",
        &["use-compression", "use_compression"],
        None,
        "use compression",
    );
    let args = construct!(UdpArgs {
        local_ip,
        local_port,
        remote_port,
        server_addr,
        server_port,
        token,
        use_encryption,
        use_compression,
        proxy_name,
    });
    single_proxy_cmd(args, FrpcCmd::Udp)
        .to_options()
        .command("udp")
        .help("Run frpc with a single udp proxy")
}

fn http_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .short('i')
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .short('l')
        .argument::<u16>("PORT");
    let custom_domains = long("custom-domain")
        .long("custom-domains")
        .long("custom_domain")
        .short('d')
        .argument::<String>("DOMAINS");
    let server_addr = long("server-addr")
        .long("server_addr")
        .short('s')
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .short('P')
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let subdomain = long("sd")
        .long("subdomain")
        .argument::<String>("SUB")
        .optional();
    let locations = long("locations").argument::<String>("LOCS").optional();
    let http_user = long("http-user")
        .long("http_user")
        .argument::<String>("USER")
        .optional();
    let http_pwd = long("http-pwd")
        .long("http_pwd")
        .argument::<String>("PWD")
        .optional();
    let host_header_rewrite = long("host-header-rewrite")
        .long("host_header_rewrite")
        .argument::<String>("HOST")
        .optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .short('n')
        .argument::<String>("NAME")
        .optional();
    let use_encryption = go_bool_flag_with_aliases!(
        "ue",
        &["use-encryption", "use_encryption"],
        None,
        "use encryption",
    );
    let use_compression = go_bool_flag_with_aliases!(
        "uc",
        &["use-compression", "use_compression"],
        None,
        "use compression",
    );
    let args = construct!(HttpArgs {
        local_ip,
        local_port,
        custom_domains,
        server_addr,
        server_port,
        token,
        subdomain,
        locations,
        http_user,
        http_pwd,
        host_header_rewrite,
        proxy_name,
        use_encryption,
        use_compression,
    });
    single_proxy_cmd(args, FrpcCmd::Http)
        .to_options()
        .command("http")
        .help("Run frpc with a single http proxy")
}

fn https_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .short('i')
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .short('l')
        .argument::<u16>("PORT");
    let custom_domains = long("custom-domain")
        .long("custom-domains")
        .long("custom_domain")
        .short('d')
        .argument::<String>("DOMAINS");
    let server_addr = long("server-addr")
        .long("server_addr")
        .short('s')
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .short('P')
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let subdomain = long("sd")
        .long("subdomain")
        .argument::<String>("SUB")
        .optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .short('n')
        .argument::<String>("NAME")
        .optional();
    let use_encryption = go_bool_flag_with_aliases!(
        "ue",
        &["use-encryption", "use_encryption"],
        None,
        "use encryption",
    );
    let use_compression = go_bool_flag_with_aliases!(
        "uc",
        &["use-compression", "use_compression"],
        None,
        "use compression",
    );
    let args = construct!(HttpsArgs {
        local_ip,
        local_port,
        custom_domains,
        server_addr,
        server_port,
        token,
        subdomain,
        proxy_name,
        use_encryption,
        use_compression,
    });
    single_proxy_cmd(args, FrpcCmd::Https)
        .to_options()
        .command("https")
        .help("Run frpc with a single https proxy")
}

fn stcp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .short('i')
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .short('l')
        .argument::<u16>("PORT");
    let sk = long("sk").argument::<String>("SECRET");
    let server_name = long("tls-server-name")
        .long("server-name")
        .long("server_name")
        .argument::<String>("NAME")
        .optional();
    let server_addr = long("server-addr")
        .long("server_addr")
        .short('s')
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .short('P')
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    // Go registers `-n/--proxy-name` on every proxy surface, this one included;
    // frp-rs's `--tls-server-name` above is where the name used to come from.
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .short('n')
        .argument::<String>("NAME")
        .optional();
    let use_encryption = go_bool_flag_with_aliases!(
        "ue",
        &["use-encryption", "use_encryption"],
        None,
        "use encryption",
    );
    let use_compression = go_bool_flag_with_aliases!(
        "uc",
        &["use-compression", "use_compression"],
        None,
        "use compression",
    );
    let args = construct!(StcpArgs {
        sk,
        server_name,
        local_ip,
        local_port,
        server_addr,
        server_port,
        token,
        proxy_name,
        use_encryption,
        use_compression,
    });
    single_proxy_cmd(args, FrpcCmd::Stcp)
        .to_options()
        .command("stcp")
        .help("Run frpc with a single stcp proxy")
}

fn xtcp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .short('i')
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .short('l')
        .argument::<u16>("PORT");
    let sk = long("sk").argument::<String>("SECRET");
    let server_name = long("tls-server-name")
        .long("server-name")
        .long("server_name")
        .argument::<String>("NAME")
        .optional();
    let server_addr = long("server-addr")
        .long("server_addr")
        .short('s')
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .short('P')
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .short('n')
        .argument::<String>("NAME")
        .optional();
    let use_encryption = go_bool_flag_with_aliases!(
        "ue",
        &["use-encryption", "use_encryption"],
        None,
        "use encryption",
    );
    let use_compression = go_bool_flag_with_aliases!(
        "uc",
        &["use-compression", "use_compression"],
        None,
        "use compression",
    );
    let args = construct!(XtcpArgs {
        sk,
        server_name,
        local_ip,
        local_port,
        server_addr,
        server_port,
        token,
        proxy_name,
        use_encryption,
        use_compression,
    });
    single_proxy_cmd(args, FrpcCmd::Xtcp)
        .to_options()
        .command("xtcp")
        .help("Run frpc with a single xtcp proxy")
}

fn sudp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .short('i')
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .short('l')
        .argument::<u16>("PORT");
    // frp-rs extension: Go's `frpc sudp` registers **no** remote-port flag at
    // all, and the v0.71.0 binary refuses both spellings (`unknown shorthand
    // flag: 'r'`, `unknown flag: --remote-port`). The long form predates this
    // branch and stays for command lines written against it; it deliberately
    // carries no `-r`, so it can never be mistaken for Go's tcp/udp row. It is
    // still **required** here (no fallback): that is pre-existing behaviour this
    // round did not change, and it is recorded as a residual — a Go-shaped
    // `frpc sudp --sk s -l 1` parses on Go but not on frp-rs.
    let remote_port = long("remote-port")
        .long("remote_port")
        .argument::<u16>("PORT");
    let server_addr = long("server-addr")
        .long("server_addr")
        .short('s')
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .short('P')
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    // Go registers `--sk` on this surface too; frp-rs used to leave sudp with
    // no way to set the visitor secret key. Optional, like Go (default "").
    let sk = long("sk").argument::<String>("SECRET").optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .short('n')
        .argument::<String>("NAME")
        .optional();
    let use_encryption = go_bool_flag_with_aliases!(
        "ue",
        &["use-encryption", "use_encryption"],
        None,
        "use encryption",
    );
    let use_compression = go_bool_flag_with_aliases!(
        "uc",
        &["use-compression", "use_compression"],
        None,
        "use compression",
    );
    let args = construct!(SudpArgs {
        local_ip,
        local_port,
        remote_port,
        server_addr,
        server_port,
        token,
        sk,
        proxy_name,
        use_encryption,
        use_compression,
    });
    single_proxy_cmd(args, FrpcCmd::Sudp)
        .to_options()
        .command("sudp")
        .help("Run frpc with a single sudp proxy")
}

fn tcpmux_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .short('i')
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .short('l')
        .argument::<u16>("PORT");
    // frp-rs's own tcpmux port flag, kept for compatibility with command lines
    // written against it. Go's `frpc tcpmux` has **no** port flag at all: its
    // help carries neither `--remote-port` nor anything else numeric beyond
    // `--local-port`, because the front listens on the server's
    // `tcpmuxHTTPConnectPort`, and frp-rs's server never reads a tcpmux proxy's
    // `remote_port` either. It is optional (Go's own command line does not carry
    // it) and its row is an frp-rs extension.
    let mux_port = long("mux-port")
        .long("mux_port")
        .argument::<u16>("PORT")
        .fallback(0);
    // Go's `--mux string` names the multiplexer — it is **not** the port. The
    // same spelling means the same thing in frp-server's SSH gateway
    // (`frp-server/src/ssh_gateway.rs:718`), and `ProxyConfig::multiplexer`
    // (frp-core/src/config/client.rs:723) is where it lands. A literal
    // `--mux-port`→`--mux` rename would have rendered `--mux int` and rejected
    // Go's string value; this is the flag Go actually has.
    let mux = long("mux").argument::<String>("MUX").optional();
    // Go registers the same domain pair here as on http/https (`custom_domain`
    // `-d`, `sd`); frp-rs's server already routes on them
    // (`frp-server/src/control/proxy_ops/vhost.rs:33`). Comma-joined like http.
    let custom_domains = long("custom-domain")
        .long("custom-domains")
        .long("custom_domain")
        .short('d')
        .argument::<String>("DOMAINS")
        .optional();
    let subdomain = long("sd")
        .long("subdomain")
        .argument::<String>("SUB")
        .optional();
    let server_addr = long("server-addr")
        .long("server_addr")
        .short('s')
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .short('P')
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .short('n')
        .argument::<String>("NAME")
        .optional();
    let use_encryption = go_bool_flag_with_aliases!(
        "ue",
        &["use-encryption", "use_encryption"],
        None,
        "use encryption",
    );
    let use_compression = go_bool_flag_with_aliases!(
        "uc",
        &["use-compression", "use_compression"],
        None,
        "use compression",
    );
    let args = construct!(TcpmuxArgs {
        local_ip,
        local_port,
        mux_port,
        mux,
        custom_domains,
        subdomain,
        server_addr,
        server_port,
        token,
        proxy_name,
        use_encryption,
        use_compression,
    });
    single_proxy_cmd(args, FrpcCmd::Tcpmux)
        .to_options()
        .command("tcpmux")
        .help("Run frpc with a single tcpmux proxy")
}

fn verify_cmd() -> impl Parser<FrpcCmd> {
    // `-c` is required here and last-wins on repetition — see [`config_arg`].
    let config = config_arg();
    // With strict off, verify accepts unknown fields, matching Go
    // (cmd/frpc/sub/verify.go passes strictConfigMode to LoadClientConfig).
    let strict_config = strict_config_parser();
    // `--allow-unsafe` is **read** here, not ignored: Go's verify consults the
    // same persistent flag through `ValidateClientConfig` (measured: rc 1
    // without `--allow-unsafe TokenSourceExec`, rc 0 with it), and frp-rs's
    // load path now runs that gate — see
    // [`crate::config::load_client_config_with_presence_checked`].
    let allow_unsafe = allow_unsafe_parser();
    let args = construct!(VerifyArgs {
        config,
        strict_config,
        allow_unsafe
    });
    construct!(args, ignored_admin_root_flags_except_allow_unsafe())
        .map(|(args, _)| args)
        .to_options()
        .command("verify")
        .help("Verify that the configuration is valid")
        .map(FrpcCmd::Verify)
}

fn reload_cmd() -> impl Parser<FrpcCmd> {
    // Last-wins on repetition; still optional here — see [`config_arg`].
    let config = config_arg().optional();
    // The parsed value is sent to the running frpc as `{"strictConfig":...}`
    // (frpc run_reload → /api/reload), so it matters beyond the local load.
    let strict_config = strict_config_parser();
    let admin_addr = long("admin-addr")
        .long("admin_addr")
        .argument::<String>("IP")
        .optional();
    let admin_port = long("admin-port")
        .long("admin_port")
        .argument::<u16>("PORT")
        .optional();
    let admin_user = long("admin-user")
        .long("admin_user")
        .argument::<String>("USER")
        .optional();
    let admin_pwd = long("admin-pwd")
        .long("admin_pwd")
        .argument::<String>("PWD")
        .optional();
    let api_timeout = api_timeout_parser();
    let args = construct!(ReloadArgs {
        config,
        strict_config,
        admin_addr,
        admin_port,
        admin_user,
        admin_pwd,
        api_timeout
    });
    construct!(args, ignored_admin_root_flags())
        .map(|(args, _)| args)
        .to_options()
        .command("reload")
        .help("Reload running frpc configuration")
        .map(FrpcCmd::Reload)
}

fn status_cmd() -> impl Parser<FrpcCmd> {
    // Last-wins on repetition; still optional here — see [`config_arg`].
    let config = config_arg().optional();
    // Probe on Go v0.71.0: `frpc status --strict-config=false -c bad.toml` is
    // accepted and tolerates unknown fields — `status` inherits the persistent
    // rootCmd flag like the other admin subcommands.
    let strict_config = strict_config_parser();
    // frp-rs-only flag: Go's `frpc status` has no `--json` at all (measured,
    // `Error: unknown flag: --json`, rc 1, for every spelling), so there is no
    // Go behaviour to match. It goes through the shared parser so that every
    // bool on the client answers `--flag=<bool>` uniformly; the value form is
    // an frp-rs extension (recorded in `docs/developing.md`).
    let json = go_bool_flag_rs_only!("json", None, None, "Output the status as JSON");
    let admin_addr = long("admin-addr")
        .long("admin_addr")
        .argument::<String>("IP")
        .optional();
    let admin_port = long("admin-port")
        .long("admin_port")
        .argument::<u16>("PORT")
        .optional();
    let admin_user = long("admin-user")
        .long("admin_user")
        .argument::<String>("USER")
        .optional();
    let admin_pwd = long("admin-pwd")
        .long("admin_pwd")
        .argument::<String>("PWD")
        .optional();
    let api_timeout = api_timeout_parser();
    let args = construct!(StatusArgs {
        config,
        strict_config,
        json,
        admin_addr,
        admin_port,
        admin_user,
        admin_pwd,
        api_timeout
    });
    construct!(args, ignored_admin_root_flags())
        .map(|(args, _)| args)
        .to_options()
        .command("status")
        .help("Query running frpc proxy status")
        .map(FrpcCmd::Status)
}

/// `frpc stop` — Go frp v0.71.0 `cmd/frpc/sub/admin.go:42` registers it with
/// the short text `Stop the running frpc`, the same config load / port refusal
/// as the other two admin commands, and the same `--api-timeout` flag.
fn stop_cmd() -> impl Parser<FrpcCmd> {
    // Last-wins on repetition; still optional here — see [`config_arg`].
    let config = config_arg().optional();
    let strict_config = strict_config_parser();
    let admin_addr = long("admin-addr")
        .long("admin_addr")
        .argument::<String>("IP")
        .optional();
    let admin_port = long("admin-port")
        .long("admin_port")
        .argument::<u16>("PORT")
        .optional();
    let admin_user = long("admin-user")
        .long("admin_user")
        .argument::<String>("USER")
        .optional();
    let admin_pwd = long("admin-pwd")
        .long("admin_pwd")
        .argument::<String>("PWD")
        .optional();
    let api_timeout = api_timeout_parser();
    let args = construct!(StopArgs {
        config,
        strict_config,
        admin_addr,
        admin_port,
        admin_user,
        admin_pwd,
        api_timeout
    });
    construct!(args, ignored_admin_root_flags())
        .map(|(args, _)| args)
        .to_options()
        .command("stop")
        .help("Stop the running frpc")
        .map(FrpcCmd::Stop)
}

/// Compose all frpc subcommands + run-mode fallback.
///
/// The `--version` **exit is not here** — see [`parse_frpc_args`]. It used to
/// be a closure on this branch, and bpaf's `ParseOrElse` evaluates every
/// alternative on a forked state, so that closure ran during speculative
/// branch exploration: measured at the base commit, `frpc --nope=1 --version`
/// and `frpc verify --version` both printed `frpc 0.71.0 (Rust)` with exit 0
/// (Go: rc 1 `unknown flag: --nope`, rc 0 with `verify` actually running),
/// because the `println!`+`exit` fired before the leftover-token and
/// branch-choice logic could run. Checking after `run()` returns is also what
/// `frps` does ([`parse_frps_args`]) and what makes `--version=foo` a parse
/// error instead of a version print.
fn frpc_parser() -> impl Parser<FrpcCmd> {
    let run = run_mode().map(FrpcCmd::Run);

    construct!([
        tcp_cmd(),
        udp_cmd(),
        http_cmd(),
        https_cmd(),
        stcp_cmd(),
        xtcp_cmd(),
        sudp_cmd(),
        tcpmux_cmd(),
        verify_cmd(),
        reload_cmd(),
        status_cmd(),
        stop_cmd(),
        run,
    ])
}

/// Parse frpc CLI args.
pub fn parse_frpc_args() -> FrpcCmd {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let (name, rest) = cli_args(&argv);
    // Go's pflag consumes a `-`-prefixed token as a config flag's value; bpaf
    // only refuses the tokens it classifies as flags (see
    // [`rewrite_config_dash_values`]). Shared with `frps` through
    // [`prepared_cli_argv`]; this call site is what makes the rewrite **and**
    // the subcommand hoist apply to every `frpc` invocation.
    // `warn_if_strict_config_space_form_used` keeps reading the original argv.
    let parse_argv = prepared_cli_argv(&rest, RootCommand::Frpc);
    let args = run_cli(
        frpc_parser()
            .to_options()
            .descr("frpc is the client of frp-rs (https://github.com/fatedier/frp)"),
        name,
        &parse_argv,
        help_request(RootCommand::Frpc, &parse_argv),
    );
    // See `parse_frps_args`: printed only for a successfully parsed argv whose
    // `--strict-config` token was followed by a consumed bool value — i.e. the
    // frp-rs space-separated extension, on every `frpc` parser (run, verify,
    // reload, status, stop).
    warn_if_strict_config_space_form_used(&argv);
    // `--version` is acted on **after** the parse, not inside `frpc_parser()`
    // (see that function): Go registers it as a persistent rootCmd bool and
    // only the root command's `RunE` prints a version, so `-v`/`--version` must
    // not short-circuit a parse that is going to fail. `--version=false` and
    // `--version=0` therefore start the client, exactly as on Go (measured
    // rc 124 there, bounded); `--version=foo` is the pflag value error (rc 1).
    if let FrpcCmd::Run(args) = &args {
        if args.show_version {
            println!("frpc {} (Rust)", crate::VERSION);
            std::process::exit(0);
        }
    }
    args
}

// ──────────────────────────────────────────────────────────────────────
// CLI → Config merge layer
// ──────────────────────────────────────────────────────────────────────

impl FrpsArgs {
    /// Config file path to load. Falls back to "frps.toml" when `-c` was
    /// not given on the command line.
    ///
    /// **R2 (`TODO.md:10759`): this implicit-`./frps.toml` lane is an frp-rs
    /// extension, not Go parity.** Go binds a server config file only through
    /// `-c`; with no `-c` its run path keeps the flags-only struct
    /// (`cmd/frps/root.go:82`) and logs `frps uses command line arguments for
    /// config` (`cmd/frps/root.go:114-118`), while frp-rs loads `./frps.toml`
    /// here. The "not supplied" rule for the empty log flags therefore defers
    /// to a *file* Go would never have read on this lane: measured with a file
    /// writing `[log] level = "warn"`, `--log-level ""` keeps `warn`
    /// (0 `INFO`) and `--log-level info` raises it (11 `INFO`) — pinned by
    /// `frps/tests/log_completion.rs:605`. Making the lane argv-identical to
    /// Go's flags-only lane is a product decision, not a bug fix; the
    /// divergence is recorded in `docs/config.md` § `log.level`.
    pub fn config_path(&self) -> String {
        self.config
            .clone()
            .unwrap_or_else(|| "frps.toml".to_string())
    }

    /// Whether CLI config flags may override the loaded config file.
    /// Go frp v0.70.1 parity: with an explicit `-c` (or `--config-dir`) the
    /// file is authoritative and flags are ignored; without `-c` the CLI
    /// flags act as overrides on top of the default config file (audit task
    /// 9 finding 5).
    pub fn cli_overrides_enabled(&self) -> bool {
        self.config.is_none() && self.config_dir.is_none()
    }

    /// Override ServerConfig fields with CLI values. Only fields explicitly
    /// set on the command line (`Some`) override config file values.
    /// Callers should skip this entirely when
    /// [`cli_overrides_enabled`](FrpsArgs::cli_overrides_enabled) is false
    /// (Go frp v0.70.1 gives the config file precedence when `-c` is given).
    ///
    /// The three `[log]` fields are the exception that keeps this overlay from
    /// being destructive: an explicitly supplied but **empty** `--log-level ""`
    /// / `--log-file ""`, and an explicitly supplied `--log-max-days 0`, are all
    /// treated as *not supplied*, so the file's `[log]` value survives. Each is
    /// Go's `util.EmptyOr` zero value and each would otherwise be filled by
    /// `LogConfig::complete` before the resolver saw it; see the log arms below.
    ///
    /// Returns the listener **ports** it applied, because the
    /// overlay runs after the load that records the file's own port requests, so
    /// only the caller can merge the two into one [`ConfigPresence`]. `frps`
    /// hands the result to
    /// [`ConfigPresence::record_applied_reader_gated_ports`]; a **zero** port
    /// counts as not supplied, matching `port_requested` / `sub_port_requested`
    /// on the file path. `web_server.port` is joined there by `kcp_bind_port`
    /// and `quic_bind_port`, the two `frp-core`-gated ports this overlay can
    /// write; the ports with no CLI flag (`ssh_tunnel_gateway.bind_port`,
    /// `websocket_port`) have no overlay half.
    ///
    /// [`ConfigPresence`]: crate::config::ConfigPresence
    /// [`ConfigPresence::record_applied_reader_gated_ports`]:
    ///     crate::config::ConfigPresence::record_applied_reader_gated_ports
    pub fn override_server_config(
        &self,
        cfg: &mut crate::config::ServerConfig,
    ) -> crate::config::AppliedReaderGatedPorts {
        let mut applied = crate::config::AppliedReaderGatedPorts::default();
        if let Some(ref v) = self.token {
            cfg.auth.token = v.clone();
        }
        if let Some(ref v) = self.allow_ports {
            cfg.allow_ports = v.clone();
        }
        if let Some(ref v) = self.bind_addr {
            cfg.bind_addr = v.clone();
        }
        if let Some(v) = self.bind_port {
            cfg.bind_port = v;
        }
        if let Some(ref v) = self.proxy_bind_addr {
            cfg.proxy_bind_addr = v.clone();
        }

        // Log. `--log-file ""`, `--log-level ""` and `--log-max-days 0` are
        // Go's zero values, which `LogConfig::complete` fills with
        // `console`/`info`/`3` (`frp-core/src/config/server.rs`). Writing the
        // zero value into the config here would therefore *raise* a file's
        // explicitly non-default `level`, `to` or `max_days` back to Go's
        // default on the one lane that applies overrides, defeating the
        // "empty/zero CLI means not supplied" rule the resolvers in
        // `frp-core/src/logging.rs` already apply to both binaries:
        // `resolve_log_level` filters `""`, `resolve_log_file` filters `""`
        // and `resolve_log_max_days` filters `0`. Go's `-c` lane leaves the
        // file's value too (both binaries, measured on v0.71.0), and this lane
        // also read a config file (`config_path()` defaults to `frps.toml`),
        // so the file's value must survive.
        if let Some(ref v) = self.log_file {
            if !v.is_empty() {
                cfg.log.file = v.clone();
            }
        }
        if let Some(ref v) = self.log_level {
            if !v.is_empty() {
                cfg.log.level = v.clone();
            }
        }
        if let Some(v) = self.log_max_days {
            if v != 0 {
                cfg.log.max_days = v;
            }
        }
        // `--log-format` has no `LogConfig::complete` slot and no Go analogue
        // on the file lane, so it keeps the raw write-through; see the
        // `log_flag_zero_values_do_not_override_the_config_file` pin below.
        if let Some(ref v) = self.log_format {
            cfg.log.format = v.clone();
        }

        // Transport / ports
        //
        // The two feature-gated bind ports are also **recorded** here, like
        // `web_server.port` below: this overlay runs after the load that records
        // the file's own request, so the write is a second source of the same
        // request and has to be merged back into `ConfigPresence`
        // (`record_applied_reader_gated_ports`). Without it
        // `frps --kcp-bind-port 7100` (no `-c`/`--config-dir`) in a build whose
        // listener is compiled out binds nothing and says nothing, while the
        // identical `kcp_bind_port = 7100` in a file warns. A zero port is "not
        // supplied" on the file path too (`port_requested`), so it is not
        // reported.
        #[cfg(feature = "kcp")]
        if let Some(v) = self.kcp_bind_port {
            cfg.kcp_bind_port = v;
            applied.kcp_bind_port = v != 0;
        }
        #[cfg(feature = "quic")]
        if let Some(v) = self.quic_bind_port {
            cfg.quic_bind_port = v;
            applied.quic_bind_port = v != 0;
        }
        if let Some(v) = self.vhost_http_port {
            cfg.vhost_http_port = v;
        }
        if let Some(v) = self.vhost_https_port {
            cfg.vhost_https_port = v;
        }
        if let Some(v) = self.vhost_http_timeout {
            cfg.vhost_http_timeout = v;
        }
        if let Some(ref v) = self.subdomain_host {
            cfg.sub_domain_host = v.clone();
        }
        if let Some(v) = self.max_ports_per_client {
            cfg.max_ports_per_client = v;
        }
        if self.tls_only {
            cfg.tls_only = true;
        }

        // Dashboard
        if let Some(ref v) = self.dashboard_addr {
            cfg.web_server.addr = v.clone();
        }
        if let Some(v) = self.dashboard_port {
            cfg.web_server.port = v;
            // A zero port is "not supplied" on the file path too
            // (`sub_port_requested`); only a real request is reported, so
            // `--dashboard-port 0` stays as silent as `port = 0`.
            applied.web_server_port = v != 0;
        }
        if let Some(ref v) = self.dashboard_user {
            cfg.web_server.user = v.clone();
        }
        if let Some(ref v) = self.dashboard_pwd {
            cfg.web_server.password = v.clone();
        }
        if self.enable_prometheus {
            cfg.web_server.enable_prometheus = true;
        }
        if let Some(ref v) = self.dashboard_tls_cert_file {
            cfg.web_server.tls_cert_file = v.clone();
        }
        if let Some(ref v) = self.dashboard_tls_key_file {
            cfg.web_server.tls_key_file = v.clone();
        }
        // dashboard_tls_mode: no config field needed — TLS activates when both
        // cert_file and key_file are non-empty (implicit detection, matching Go frp).
        applied
    }
}

/// Build a minimal ClientConfig from single-proxy subcommand args (no config file needed).
pub fn build_single_proxy_config(
    server_addr: &str,
    server_port: u16,
    token: Option<&str>,
    proxy: crate::config::ProxyConfig,
) -> crate::config::ClientConfig {
    crate::config::ClientConfig {
        server_addr: server_addr.to_string(),
        server_port,
        token: token.unwrap_or("").to_string(),
        proxies: vec![proxy],
        login_fail_exit: true,
        ..Default::default()
    }
}

// ─── ProxyConfig builders for each subcommand type ───────────────────

impl TcpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self
                .proxy_name
                .clone()
                .unwrap_or_else(|| format!("tcp-{}->{}", self.local_port, self.remote_port)),
            proxy_type: "tcp".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            remote_port: self.remote_port,
            use_encryption: self.use_encryption,
            use_compression: self.use_compression,
            ..Default::default()
        }
    }
}

impl UdpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self
                .proxy_name
                .clone()
                .unwrap_or_else(|| format!("udp-{}->{}", self.local_port, self.remote_port)),
            proxy_type: "udp".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            remote_port: self.remote_port,
            use_encryption: self.use_encryption,
            use_compression: self.use_compression,
            ..Default::default()
        }
    }
}

impl HttpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let domains: Vec<String> = self
            .custom_domains
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        crate::config::ProxyConfig {
            name: self
                .proxy_name
                .clone()
                .unwrap_or_else(|| format!("http-{}", self.local_port)),
            proxy_type: "http".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            custom_domains: domains,
            subdomain: self.subdomain.clone().unwrap_or_default(),
            locations: self
                .locations
                .clone()
                .map(|l| l.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
            http_user: self.http_user.clone().unwrap_or_default(),
            http_pwd: self.http_pwd.clone().unwrap_or_default(),
            host_header_rewrite: self.host_header_rewrite.clone().unwrap_or_default(),
            use_encryption: self.use_encryption,
            use_compression: self.use_compression,
            ..Default::default()
        }
    }
}

impl HttpsArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let domains: Vec<String> = self
            .custom_domains
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        crate::config::ProxyConfig {
            name: self
                .proxy_name
                .clone()
                .unwrap_or_else(|| format!("https-{}", self.local_port)),
            proxy_type: "https".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            custom_domains: domains,
            subdomain: self.subdomain.clone().unwrap_or_default(),
            use_encryption: self.use_encryption,
            use_compression: self.use_compression,
            ..Default::default()
        }
    }
}

impl StcpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self
                .proxy_name
                .clone()
                .or_else(|| self.server_name.clone())
                .unwrap_or_else(|| "stcp-proxy".into()),
            proxy_type: "stcp".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            sk: self.sk.clone(),
            use_encryption: self.use_encryption,
            use_compression: self.use_compression,
            ..Default::default()
        }
    }
}

impl XtcpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self
                .proxy_name
                .clone()
                .or_else(|| self.server_name.clone())
                .unwrap_or_else(|| "xtcp-proxy".into()),
            proxy_type: "xtcp".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            sk: self.sk.clone(),
            use_encryption: self.use_encryption,
            use_compression: self.use_compression,
            ..Default::default()
        }
    }
}

impl SudpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self
                .proxy_name
                .clone()
                .unwrap_or_else(|| format!("sudp-{}->{}", self.local_port, self.remote_port)),
            proxy_type: "sudp".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            remote_port: self.remote_port,
            sk: self.sk.clone().unwrap_or_default(),
            use_encryption: self.use_encryption,
            use_compression: self.use_compression,
            ..Default::default()
        }
    }
}

impl TcpmuxArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self
                .proxy_name
                .clone()
                .unwrap_or_else(|| format!("tcpmux-{}", self.local_port)),
            proxy_type: "tcpmux".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            custom_domains: self
                .custom_domains
                .clone()
                .map(|d| d.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
            subdomain: self.subdomain.clone().unwrap_or_default(),
            remote_port: self.mux_port,
            multiplexer: self.mux.clone().unwrap_or_else(|| "httpconnect".into()),
            use_encryption: self.use_encryption,
            use_compression: self.use_compression,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `frps` **run-path** parser, which is `frps_args()` — the module's
    /// flag-surface tests want the root command's own arguments, and driving
    /// them through [`frps_parser`]'s alternation would let the `verify` branch
    /// answer for a run-mode argv. The whole surface is `frps_parser()`; the
    /// hoist tests below use [`run_frps_cmd`] for it.
    fn parse_frps(args: &[&str]) -> Result<FrpsArgs, bpaf::ParseFailure> {
        frps_args().to_options().run_inner(args)
    }

    fn parse_frps_verify(args: &[&str]) -> Result<VerifyArgs, bpaf::ParseFailure> {
        match frps_parser().to_options().run_inner(args)? {
            FrpsCmd::Verify(a) => Ok(a),
            other => panic!("expected the frps verify command, got {other:?}"),
        }
    }

    fn parse_frpc_run(args: &[&str]) -> Result<FrpcRunArgs, bpaf::ParseFailure> {
        match frpc_parser().to_options().run_inner(args)? {
            FrpcCmd::Run(a) => Ok(a),
            other => panic!("expected run mode, got {other:?}"),
        }
    }

    fn parse_frpc_reload(args: &[&str]) -> Result<ReloadArgs, bpaf::ParseFailure> {
        match frpc_parser().to_options().run_inner(args)? {
            FrpcCmd::Reload(a) => Ok(a),
            other => panic!("expected reload command, got {other:?}"),
        }
    }

    fn parse_frpc_verify(args: &[&str]) -> Result<VerifyArgs, bpaf::ParseFailure> {
        match frpc_parser().to_options().run_inner(args)? {
            FrpcCmd::Verify(a) => Ok(a),
            other => panic!("expected verify command, got {other:?}"),
        }
    }

    /// `frpc tcp` — used by the `GO_BOOL_SITES` rows, which exercise Go's
    /// `--ue`/`--uc` (and their frp-rs aliases) on this one surface; every proxy
    /// surface takes them, and that is pinned separately by
    /// [`every_proxy_surface_accepts_go_bool_names_and_their_frp_rs_aliases`].
    fn parse_frpc_tcp(args: &[&str]) -> Result<TcpArgs, bpaf::ParseFailure> {
        match frpc_parser().to_options().run_inner(args)? {
            FrpcCmd::Tcp(a) => Ok(a),
            other => panic!("expected tcp command, got {other:?}"),
        }
    }

    /// Parse any `frpc <proxy>` command line and hand back the whole command, so
    /// a probe can cover the surfaces that have no dedicated helper.
    fn parse_frpc_proxy(args: &[&str]) -> Result<FrpcCmd, bpaf::ParseFailure> {
        frpc_parser().to_options().run_inner(args)
    }

    fn parse_frpc_status(args: &[&str]) -> Result<StatusArgs, bpaf::ParseFailure> {
        match frpc_parser().to_options().run_inner(args)? {
            FrpcCmd::Status(a) => Ok(a),
            other => panic!("expected status command, got {other:?}"),
        }
    }

    fn parse_frpc_stop(args: &[&str]) -> Result<StopArgs, bpaf::ParseFailure> {
        match frpc_parser().to_options().run_inner(args)? {
            FrpcCmd::Stop(a) => Ok(a),
            other => panic!("expected stop command, got {other:?}"),
        }
    }

    /// The `--allow-unsafe` reader on its own ([`allow_unsafe_parser`]), so a
    /// test can compare the **values** pflag would see instead of only whether a
    /// command accepted the argv.
    fn read_allow_unsafe(args: &[&str]) -> Result<Vec<String>, bpaf::ParseFailure> {
        allow_unsafe_parser().to_options().run_inner(args)
    }

    /// The ignored twin on its own ([`ignored_allow_unsafe`]): the value is
    /// dropped on the surfaces that use it, but it must still be read — and
    /// refused when malformed — exactly like [`read_allow_unsafe`].
    fn read_ignored_allow_unsafe(args: &[&str]) -> Result<Vec<String>, bpaf::ParseFailure> {
        ignored_allow_unsafe().to_options().run_inner(args)
    }

    /// Every parser that accepts `--strict-config`, as `(label, argv)` —
    /// `frps`'s run path, `frps verify`, then `frpc`'s `run`/`verify`/`reload`/
    /// `status`/`stop`. `-c x.toml` is present throughout because both `verify`
    /// commands need a config path in the argv; the other five fall back and
    /// never read the file (these helpers only run the bpaf parser).
    ///
    /// `frps verify` belongs in this table: Go registers `--strict_config` on
    /// `frps`'s **root** command (`cmd/frps/root.go:46`) and `verifyCmd` reads
    /// it (`cmd/frps/verify.go:40`), so it is the same persistent pflag and must
    /// take the same spellings and the same default. The table's purpose is
    /// exactly that "one flag, every parser" claim, and leaving the new parser
    /// out would let it drift silently.
    fn strict_config_argv(flag: &[&str]) -> Vec<(&'static str, Vec<String>)> {
        let base: Vec<String> = ["-c", "x.toml"]
            .iter()
            .chain(flag.iter())
            .map(|s| s.to_string())
            .collect();
        let prefixed = |cmd: &str| -> Vec<String> {
            let mut v = vec![cmd.to_string()];
            v.extend(base.iter().cloned());
            v
        };
        vec![
            ("frps", base.clone()),
            ("frps verify", prefixed("verify")),
            ("frpc run", base.clone()),
            ("frpc verify", prefixed("verify")),
            ("frpc reload", prefixed("reload")),
            ("frpc status", prefixed("status")),
            ("frpc stop", prefixed("stop")),
        ]
    }

    fn strict_config_of(label: &str, argv: &[String]) -> Result<bool, bpaf::ParseFailure> {
        let a: Vec<&str> = argv.iter().map(String::as_str).collect();
        match label {
            "frps" => parse_frps(&a).map(|x| x.strict_config),
            "frps verify" => parse_frps_verify(&a).map(|x| x.strict_config),
            "frpc run" => parse_frpc_run(&a).map(|x| x.strict_config),
            "frpc verify" => parse_frpc_verify(&a).map(|x| x.strict_config),
            "frpc reload" => parse_frpc_reload(&a).map(|x| x.strict_config),
            "frpc status" => parse_frpc_status(&a).map(|x| x.strict_config),
            "frpc stop" => parse_frpc_stop(&a).map(|x| x.strict_config),
            other => panic!("unknown parser {other}"),
        }
    }

    #[test]
    fn strict_config_defaults_to_true() {
        // Measured Go v0.71.0 row (flag absent): `frpc reload -c <config with
        // an unknown top-level key>` → `json: unknown field
        // "notAKnownFrpKey"`, rc 1 — strict is on. Every parser defaults the
        // same way. See `docs/developing.md` § "`--strict-config`: the
        // space-separated value form".
        for (label, argv) in strict_config_argv(&[]) {
            assert!(
                strict_config_of(label, &argv)
                    .unwrap_or_else(|e| panic!("{label} {argv:?} must parse: {e:?}")),
                "{label}"
            );
        }
    }

    #[test]
    fn strict_config_bare_flag_is_true() {
        // Measured Go v0.71.0 row (bare flag): identical to absent — strict
        // stays on in both binaries. Go-faithful, and Go's
        // `config.WordSepNormalizeFunc` folds `_` to `-`, so the underscore
        // spelling is Go parity too (measured: `frpc reload --strict_config -c
        // <unknown-key config>` → `json: unknown field "notAKnownFrpKey"`,
        // rc 1 on Go and the same strict refusal on frp-rs).
        for args in [&["--strict-config"][..], &["--strict_config"][..]] {
            for (label, argv) in strict_config_argv(args) {
                assert!(
                    strict_config_of(label, &argv)
                        .unwrap_or_else(|e| panic!("{label} {args:?} must parse: {e:?}")),
                    "{label} {args:?}"
                );
            }
        }
    }

    #[test]
    fn strict_config_equals_false_parses_and_disables() {
        // Audit task 9 finding 3: `--strict-config=false` was a parse error
        // with a plain switch; it must parse and disable strict mode.
        // Measured Go v0.71.0 row: lenient — `frpc reload
        // --strict-config=false -c <unknown-key config>` dials the config's
        // web server port instead of reporting the unknown field. This is the
        // **Go-faithful value spelling** on every parser.
        for args in [
            &["--strict-config=false"][..],
            &["--strict_config=false"][..],
        ] {
            for (label, argv) in strict_config_argv(args) {
                assert!(
                    !strict_config_of(label, &argv)
                        .unwrap_or_else(|e| panic!("{label} {args:?} must parse: {e:?}")),
                    "{label} {args:?}"
                );
            }
        }
    }

    #[test]
    fn strict_config_equals_true_parses() {
        // Measured Go v0.71.0 row: `=true` is strict on both binaries. On the
        // client that is observable end-to-end: `frpc reload
        // --strict-config=true -c <unknown-key config>` is `json: unknown
        // field "notAKnownFrpKey"`, rc 1.
        for args in [&["--strict-config=true"][..], &["--strict_config=true"][..]] {
            for (label, argv) in strict_config_argv(args) {
                assert!(
                    strict_config_of(label, &argv)
                        .unwrap_or_else(|e| panic!("{label} {args:?} must parse: {e:?}")),
                    "{label} {args:?}"
                );
            }
        }
    }

    #[test]
    fn strict_config_space_separated_value_parses() {
        // The **documented frp-rs extension**, kept rather than dropped
        // (decision + measurements: `docs/developing.md` § "`--strict-config`:
        // the space-separated value form"). frp-rs consumes the next token as
        // the value, so `--strict-config false` disables strict mode exactly
        // like `--strict-config=false`.
        //
        // Measured Go v0.71.0, same argv: the token is **not** consumed.
        // `frpc reload --strict-config false -c <unknown-key config>` stays
        // strict and prints `json: unknown field "notAKnownFrpKey"`, rc 1
        // (`false` is an unused positional there); on the root command, which
        // takes no positional, it is `Error: unknown command "false" for
        // "frpc"`, rc 1. Uniform on all six parsers here, both hyphen and
        // underscore spellings.
        for args in [
            &["--strict-config", "false"][..],
            &["--strict_config", "false"][..],
        ] {
            for (label, argv) in strict_config_argv(args) {
                assert!(
                    !strict_config_of(label, &argv)
                        .unwrap_or_else(|e| panic!("{label} {args:?} must parse: {e:?}")),
                    "{label} {args:?}"
                );
            }
        }
        // Go strconv.ParseBool spellings — the value grammar is Go's, only the
        // token's position differs from pflag.
        for v in ["1", "t", "T", "TRUE", "true", "True"] {
            for (label, argv) in strict_config_argv(&["--strict-config", v]) {
                assert!(
                    strict_config_of(label, &argv)
                        .unwrap_or_else(|e| panic!("{label} {v} must parse: {e:?}")),
                    "{label} {v}"
                );
            }
        }
        for v in ["0", "f", "F", "FALSE", "false", "False"] {
            for (label, argv) in strict_config_argv(&["--strict-config", v]) {
                assert!(
                    !strict_config_of(label, &argv)
                        .unwrap_or_else(|e| panic!("{label} {v} must parse: {e:?}")),
                    "{label} {v}"
                );
            }
        }
    }

    #[test]
    fn reload_strict_config_matches_run_mode_semantics() {
        // Go frp v0.71.0: --strict_config is a persistent rootCmd flag
        // (default true), so the reload subcommand inherits run-mode
        // semantics — absent → true, bare → true, `--strict-config=false` →
        // false (matches Go pflag). The space-separated
        // `--strict-config false` → false is an frp-rs extension, NOT Go pflag
        // semantics (measured: Go keeps strict=true and leaves `false` as an
        // unused positional argument — see `parse_go_bool`). The old plain
        // switch made the `=false` form a parse error
        // and the absent default false; the value is sent to the running
        // frpc as `{"strictConfig":...}`, so the parsed value matters.
        // The subcommand word comes first: `reload [--strict-config ...]`.
        assert!(parse_frpc_reload(&["reload"]).unwrap().strict_config);
        assert!(
            parse_frpc_reload(&["reload", "--strict-config"])
                .unwrap()
                .strict_config
        );
        assert!(
            !parse_frpc_reload(&["reload", "--strict-config=false"])
                .unwrap()
                .strict_config
        );
        assert!(
            !parse_frpc_reload(&["reload", "--strict-config", "false"])
                .unwrap()
                .strict_config
        );
        assert!(
            parse_frpc_reload(&["reload", "--strict_config", "true"])
                .unwrap()
                .strict_config
        );
    }

    #[test]
    fn verify_strict_config_parses_like_run_mode() {
        // Go frp v0.71.0: --strict_config is a persistent rootCmd flag
        // (default true), so the `verify` subcommand inherits run-mode
        // semantics — absent → true, bare → true, `--strict-config=false` →
        // false (matches Go pflag), while the space-separated
        // `--strict-config false` → false is an frp-rs extension, NOT Go pflag
        // semantics (see `parse_go_bool`)
        // (cmd/frpc/sub/verify.go passes strictConfigMode to
        // config.LoadClientConfig). Round-8 fix 7e.
        let args = parse_frpc_verify(&["verify", "-c", "x.toml"]).unwrap();
        assert_eq!(args.config, "x.toml");
        assert!(
            args.strict_config,
            "verify defaults to strict config (Go rootCmd persistent flag)"
        );
        assert!(
            parse_frpc_verify(&["verify", "-c", "x.toml", "--strict-config"])
                .unwrap()
                .strict_config
        );
        assert!(
            !parse_frpc_verify(&["verify", "-c", "x.toml", "--strict-config=false"])
                .unwrap()
                .strict_config
        );
        assert!(
            !parse_frpc_verify(&["verify", "-c", "x.toml", "--strict-config", "false"])
                .unwrap()
                .strict_config
        );
        assert!(
            parse_frpc_verify(&["verify", "-c", "x.toml", "--strict_config=true"])
                .unwrap()
                .strict_config
        );
    }

    #[test]
    fn strict_config_invalid_value_errors_cleanly() {
        // Both non-bool spellings are refused on every parser with the same
        // message. The two rows are **different** divergences, both recorded in
        // `docs/developing.md` § "`--strict-config`: the space-separated value
        // form":
        //
        // * `--strict-config foo` (space) — the value branch fails
        //   `parse_go_bool` and `or_else` backtracks to the switch, which
        //   consumes only the flag; the leftover `foo` then fails the parse
        //   rather than being swallowed. Measured Go v0.71.0: the stray token
        //   is **ignored**, strict stays `true` and the config is still loaded
        //   (`frpc reload --strict-config foo -c <unknown-key config>` →
        //   `json: unknown field "notAKnownFrpKey"`, rc 1). frp-rs refuses the
        //   argv and never loads the config.
        // * `--strict-config=foo` (adjacent) — Go errors as well, with pflag's
        //   own text: `Error: invalid argument "foo" for "--strict-config"
        //   flag: strconv.ParseBool: parsing "foo": invalid syntax`, rc 1.
        //   frp-rs's message is the one below.
        //
        // The exit code is 1 on both binaries for both spellings; only the
        // message — and, on the space form, whether the config is loaded — is
        // divergent. Note what this test does *not* prove: the name says
        // "cleanly", but `parse_go_bool`'s own `invalid boolean value "…"`
        // string is never user-visible — bpaf backtracks on the `Err` and the
        // leftover token is reported with the message asserted below (measured
        // on the binary for `foo`, `=foo` and the empty value). The assertion
        // here is on that user-visible message, and on the parser refusing
        // rather than silently dropping the token.
        const EXPECTED: &str = "`foo` is not expected in this context";
        for args in [
            &["--strict-config", "foo"][..],
            &["--strict_config", "foo"][..],
            &["--strict-config=foo"][..],
            &["--strict_config=foo"][..],
        ] {
            for (label, argv) in strict_config_argv(args) {
                let err = strict_config_of(label, &argv)
                    .expect_err(&format!("{label} {args:?} must be refused"))
                    .unwrap_stderr();
                assert!(err.contains(EXPECTED), "{label} {args:?}: {err:?}");
            }
        }
    }

    #[test]
    fn strict_config_bare_before_other_flags_is_true() {
        // The optional value must not swallow a following flag token: bpaf's
        // `argument` never consumes a `-`-prefixed token, so a bare
        // `--strict-config` followed by another flag still means "true".
        let args = parse_frps(&["--strict-config", "--config", "frps.toml"]).unwrap();
        assert!(args.strict_config);
        assert_eq!(args.config_path(), "frps.toml");
    }

    #[test]
    fn dashboard_addr_flag_applied_to_web_server() {
        // Audit task 9 finding 4: --dashboard-addr was parsed but never
        // applied to the config.
        let args = parse_frps(&["--dashboard-addr", "1.2.3.4"]).unwrap();
        let mut cfg = crate::config::ServerConfig::default();
        args.override_server_config(&mut cfg);
        assert_eq!(cfg.web_server.addr, "1.2.3.4");
    }

    /// `--dashboard-port` is the one reader-gated listener port the CLI overlay
    /// can write, so its request has to travel back to the caller on
    /// [`AppliedReaderGatedPorts`] — `web_server.port` is unconditional in
    /// `ServerConfig`, and the overlay runs after the load that records the
    /// *file's* request, so a returned value is the only way `frps` can hand it
    /// to the same warn path.
    ///
    /// The zero case matters as much as the non-zero one: the file path counts
    /// only a **non-zero** port (`sub_port_requested`), so `--dashboard-port 0`
    /// must not manufacture a record the file form would never produce. Pinned
    /// on the real binary by
    /// `frps/tests/warn_delivery.rs::web_server_port_warning_reaches_a_flag_user_without_a_config`.
    ///
    /// [`AppliedReaderGatedPorts`]: crate::config::AppliedReaderGatedPorts
    #[test]
    fn dashboard_port_override_reports_the_reader_gated_request() {
        let mut cfg = crate::config::ServerConfig::default();
        let applied = parse_frps(&["--dashboard-port", "7500"])
            .unwrap()
            .override_server_config(&mut cfg);
        assert_eq!(
            cfg.web_server.port, 7500,
            "the flag still reaches the config"
        );
        assert!(
            applied.web_server_port,
            "a non-zero --dashboard-port is an applied reader-gated port"
        );

        let mut cfg = crate::config::ServerConfig::default();
        let applied = parse_frps(&["--dashboard-port", "0"])
            .unwrap()
            .override_server_config(&mut cfg);
        assert_eq!(cfg.web_server.port, 0);
        assert!(
            !applied.web_server_port,
            "`--dashboard-port 0` is Go's zero value, exactly like `port = 0` in a file: \
             it requests no listener, so it must not warn"
        );

        let mut cfg = crate::config::ServerConfig::default();
        let applied = parse_frps(&[]).unwrap().override_server_config(&mut cfg);
        assert_eq!(cfg.web_server.port, 0);
        assert!(!applied.web_server_port, "no flag at all is not a request");
    }

    /// The merge `frps` performs at startup: an overlay-applied
    /// `web_server.port` becomes the same record as the file key, and only in a
    /// build whose reader is absent. The per-shape half of this claim is pinned
    /// by `frp-server/src/service.rs::dashboard_port_overlay_record_follows_this_builds_reader`
    /// (which uses the owning crate's real reader) and on the binary by
    /// `frps/tests/warn_delivery.rs`.
    #[test]
    fn recorded_overlay_port_warns_only_when_the_reader_is_absent() {
        use crate::config::{AppliedReaderGatedPorts, ConfigPresence, ListenerPortReader};

        let mut presence = ConfigPresence::default();
        presence.record_applied_reader_gated_ports(AppliedReaderGatedPorts {
            web_server_port: true,
            ..Default::default()
        });
        assert_eq!(
            presence.unhonoured_reader_gated_port_records(
                ListenerPortReader::Absent,
                ListenerPortReader::Present
            ),
            vec![crate::config::WEB_SERVER_PORT_UNHONOURED_WARNING],
            "an overlay-applied port in a build without the reader is a record"
        );
        assert!(
            presence
                .unhonoured_reader_gated_port_records(
                    ListenerPortReader::Present,
                    ListenerPortReader::Present
                )
                .is_empty(),
            "a build that binds the port must stay silent"
        );

        let mut presence = ConfigPresence::default();
        presence.record_applied_reader_gated_ports(AppliedReaderGatedPorts::default());
        assert!(
            presence
                .unhonoured_reader_gated_port_records(
                    ListenerPortReader::Absent,
                    ListenerPortReader::Absent
                )
                .is_empty(),
            "recording nothing must add nothing"
        );
    }

    /// The `--kcp-bind-port` twin of
    /// [`dashboard_port_override_reports_the_reader_gated_request`]: the overlay
    /// writes `kcp_bind_port` **and** reports the request, and the zero value is
    /// not a request. Without the report,
    /// `frps --kcp-bind-port 7100` (no `-c`) in the hand-named shape
    /// (`tiny,frp-core/kcp`, where this crate has the flag but `frp-server` has
    /// no listener) binds nothing and says nothing.
    #[cfg(feature = "kcp")]
    #[test]
    fn kcp_bind_port_override_reports_the_reader_gated_request() {
        for spelling in ["--kcp-bind-port", "--kcp_bind_port"] {
            let mut cfg = crate::config::ServerConfig::default();
            let applied = parse_frps(&[spelling, "7100"])
                .unwrap()
                .override_server_config(&mut cfg);
            assert_eq!(
                cfg.kcp_bind_port, 7100,
                "`{spelling}` must reach the config"
            );
            assert!(
                applied.kcp_bind_port,
                "a non-zero `{spelling}` is an applied listener port"
            );
        }

        let mut cfg = crate::config::ServerConfig::default();
        let applied = parse_frps(&["--kcp-bind-port", "0"])
            .unwrap()
            .override_server_config(&mut cfg);
        assert_eq!(cfg.kcp_bind_port, 0);
        assert!(
            !applied.kcp_bind_port,
            "`--kcp-bind-port 0` is Go's zero value, exactly like `kcp_bind_port = 0` \
             in a file: it requests no listener, so it must not warn"
        );

        let mut cfg = crate::config::ServerConfig::default();
        let applied = parse_frps(&[]).unwrap().override_server_config(&mut cfg);
        assert_eq!(cfg.kcp_bind_port, 0);
        assert!(!applied.kcp_bind_port, "no flag at all is not a request");
    }

    /// The `--quic-bind-port` twin of
    /// [`kcp_bind_port_override_reports_the_reader_gated_request`].
    #[cfg(feature = "quic")]
    #[test]
    fn quic_bind_port_override_reports_the_reader_gated_request() {
        for spelling in ["--quic-bind-port", "--quic_bind_port"] {
            let mut cfg = crate::config::ServerConfig::default();
            let applied = parse_frps(&[spelling, "7200"])
                .unwrap()
                .override_server_config(&mut cfg);
            assert_eq!(
                cfg.quic_bind_port, 7200,
                "`{spelling}` must reach the config"
            );
            assert!(
                applied.quic_bind_port,
                "a non-zero `{spelling}` is an applied listener port"
            );
        }

        let mut cfg = crate::config::ServerConfig::default();
        let applied = parse_frps(&["--quic-bind-port", "0"])
            .unwrap()
            .override_server_config(&mut cfg);
        assert_eq!(cfg.quic_bind_port, 0);
        assert!(
            !applied.quic_bind_port,
            "`--quic-bind-port 0` is Go's zero value, exactly like `quic_bind_port = 0` \
             in a file: it requests no listener, so it must not warn"
        );

        let mut cfg = crate::config::ServerConfig::default();
        let applied = parse_frps(&[]).unwrap().override_server_config(&mut cfg);
        assert_eq!(cfg.quic_bind_port, 0);
        assert!(!applied.quic_bind_port, "no flag at all is not a request");
    }

    /// The `frp-core`-gated half of the overlay merge, the counterpart of
    /// [`recorded_overlay_port_warns_only_when_the_reader_is_absent`]: an
    /// overlay-applied `kcp_bind_port` / `quic_bind_port` becomes the same record
    /// as the file key, and only when the caller reports no listener for it.
    ///
    /// `websocket_port` is deliberately absent: there is no
    /// `--websocket-port` flag, so it has no overlay half and
    /// `AppliedReaderGatedPorts` carries no field for it.
    #[cfg(all(feature = "kcp", feature = "quic"))]
    #[test]
    fn recorded_overlay_gated_ports_warn_only_when_the_reader_is_absent() {
        use crate::config::{
            AppliedReaderGatedPorts, ConfigPresence, GatedListenerPortReaders, ListenerPortReader,
        };

        let applied = AppliedReaderGatedPorts {
            kcp_bind_port: true,
            quic_bind_port: true,
            ..Default::default()
        };
        let no_readers = GatedListenerPortReaders::from_features(false, false, false);
        let all_readers = GatedListenerPortReaders::from_features(true, true, true);

        let mut presence = ConfigPresence::default();
        presence.record_applied_reader_gated_ports(applied);
        let records = presence.unhonoured_server_feature_key_records(no_readers);
        assert_eq!(
            records,
            vec![
                crate::config::SERVER_KCP_BIND_PORT_UNHONOURED_NO_READER_WARNING.clone(),
                crate::config::SERVER_QUIC_BIND_PORT_UNHONOURED_NO_READER_WARNING.clone(),
            ],
            "an overlay-applied gated port in a build without its listener is a record"
        );
        assert!(
            presence
                .unhonoured_server_feature_key_records(all_readers)
                .is_empty(),
            "a build that binds both ports must stay silent"
        );

        let mut presence = ConfigPresence::default();
        presence.record_applied_reader_gated_ports(AppliedReaderGatedPorts::default());
        assert!(
            presence
                .unhonoured_server_feature_key_records(no_readers)
                .is_empty(),
            "recording nothing must add nothing"
        );
        // The assertion has to be able to fail: the two reader values must be
        // distinguishable, or every comparison above holds vacuously.
        assert_ne!(ListenerPortReader::Present, ListenerPortReader::Absent);
    }

    /// `--vhost-http-timeout` is Go's `vhost_http_timeout`, registered on the
    /// persistent root so it is accepted on both the run and `verify` paths.
    /// This pins the parts a parse-only check would miss: the value reaches
    /// `ServerConfig` on the override lane, and an absent flag leaves Go's
    /// default (60, `frp-core/src/config/server.rs:249`) alone.
    #[test]
    fn vhost_http_timeout_flag_applied_to_server_config() {
        for spelling in ["--vhost-http-timeout", "--vhost_http_timeout"] {
            let args = parse_frps(&[spelling, "30"]).unwrap();
            assert_eq!(
                args.vhost_http_timeout,
                Some(30),
                "`{spelling} 30` must parse as 30"
            );
            let mut cfg = crate::config::ServerConfig::default();
            args.override_server_config(&mut cfg);
            assert_eq!(cfg.vhost_http_timeout, 30, "`{spelling}` must be applied");
        }

        let args = parse_frps(&[]).unwrap();
        assert_eq!(args.vhost_http_timeout, None);
        let mut cfg = crate::config::ServerConfig::default();
        args.override_server_config(&mut cfg);
        assert_eq!(cfg.vhost_http_timeout, 60, "absent flag keeps Go's default");

        // Go registers the flag with `Int64VarP` (`pkg/config/flags.go:237`) and
        // its config field is `int64`, so the signed boundaries are accepted and
        // only a value outside `int64` is refused. Measured on Go v0.71.0
        // (`frps verify -c <valid>`): `-1` and `-9223372036854775808` rc 0,
        // `9223372036854775807` rc 0, `9223372036854775808` and
        // `9999999999999999999` rc 1 `strconv.ParseInt … value out of range`.
        //
        // A `-`-prefixed value needs the same preparation the binaries run
        // ([`prepared_cli_argv`], `attach_flag_shaped_values`): bpaf alone reads
        // `-1` as a flag, which is why the real `frps --vhost-http-timeout -1`
        // parses (measured: it starts and exits on the config's own error, not
        // on argv).
        let parse_prepared = |argv: &[&str]| {
            let prepared: Vec<OsString> = argv.iter().map(OsString::from).collect();
            frps_args()
                .to_options()
                .run_inner(&prepared_cli_argv(&prepared, RootCommand::Frps)[..])
        };
        for (argv, expected) in [
            ("-1", -1_i64),
            ("-9223372036854775808", i64::MIN),
            ("9223372036854775807", i64::MAX),
        ] {
            let args = parse_prepared(&["--vhost-http-timeout", argv]).unwrap();
            assert_eq!(
                args.vhost_http_timeout,
                Some(expected),
                "`{argv}` is inside Go's int64 range"
            );
            let mut cfg = crate::config::ServerConfig::default();
            args.override_server_config(&mut cfg);
            assert_eq!(
                cfg.vhost_http_timeout, expected,
                "`{argv}` must reach the config signed, not refused or wrapped"
            );
        }
        for argv in ["9223372036854775808", "9999999999999999999"] {
            assert!(
                parse_prepared(&["--vhost-http-timeout", argv]).is_err(),
                "`{argv}` is outside Go's int64, so `Int64VarP` refuses it too"
            );
        }
    }

    /// `--log-level ""`, `--log-file ""` and `--log-max-days 0` are Go's zero
    /// values, and `LogConfig::complete` fills them with `info`/`console`/`3`
    /// (`frp-core/src/config/server.rs`). Writing them through this override
    /// therefore silently **raised** a config file's explicit
    /// `[log] level = "warn"` back to `info` on the one lane that applies
    /// overrides — on the pre-fix revision `3f66d823` (before `c8451157`),
    /// frps run with `frps.toml` (`[log] level = "warn"`) in the cwd and no
    /// `-c`: the empty flag was written into `[log] level` and completed to
    /// `info`, so `--log-level ""` resolved to `info` (11 `INFO` records) where
    /// no flag gave 0. That resolved-`info` output is the one this head binary
    /// still prints for `--log-level info` on the same lane: 11 `INFO` records,
    /// config `bindPort = 17531`, `[auth] token = "rev427token"`,
    /// `[log] level = "warn"`.
    /// Go v0.71.0 has no parity to claim on the *non-empty* value — with `-c`
    /// it discards the pflag-bound struct, so its file's `warn` survives an
    /// absent, empty **or** non-empty `--log-level` (0 records in all three) —
    /// and frp-rs still honours a non-empty one (open divergence R1). The shape
    /// this test pins is the *empty* value on the implicit `./frps.toml` lane,
    /// where `--log-level ""` now keeps the file's `warn` (0 `INFO` records);
    /// `frpc`, which never overlays, honoured the file throughout. The resolvers
    /// already model the zero values as absent for both binaries
    /// (`resolve_log_level`/`resolve_log_file`/`resolve_log_max_days`,
    /// `frp-core/src/logging.rs:113`, `:152`, `:207`).
    #[test]
    fn log_flag_zero_values_do_not_override_the_config_file() {
        let mut cfg = crate::config::ServerConfig::default();
        cfg.log.level = "warn".to_string();
        cfg.log.file = "logs/frps.log".to_string();
        cfg.log.max_days = 5;

        let args =
            parse_frps(&["--log-level", "", "--log-file", "", "--log-max-days", "0"]).unwrap();
        // The zero values still parse as *supplied*: it is the overlay, not the
        // parser, that treats them as absent.
        assert_eq!(args.log_level.as_deref(), Some(""));
        assert_eq!(args.log_file.as_deref(), Some(""));
        assert_eq!(args.log_max_days, Some(0));
        args.override_server_config(&mut cfg);
        // The real order (`frps/src/main.rs`): override first, then Go's completion.
        cfg.complete();
        assert_eq!(
            cfg.log.level, "warn",
            "an empty --log-level is not supplied"
        );
        assert_eq!(
            cfg.log.file, "logs/frps.log",
            "an empty --log-file is not supplied"
        );
        assert_eq!(cfg.log.max_days, 5, "a zero --log-max-days is not supplied");

        // Non-zero flags still win, so this is a zero-value filter and not
        // "ignore the CLI log flags".
        let mut cfg = crate::config::ServerConfig::default();
        cfg.log.level = "warn".to_string();
        cfg.log.max_days = 5;
        let args = parse_frps(&["--log-level", "trace", "--log-max-days", "7"]).unwrap();
        args.override_server_config(&mut cfg);
        // The real order (`frps/src/main.rs`): override first, then Go's completion.
        cfg.complete();
        assert_eq!(cfg.log.level, "trace", "a non-empty --log-level still wins");
        assert_eq!(cfg.log.max_days, 7, "a non-zero --log-max-days still wins");

        // Deliberate residue, pinned so it cannot change silently:
        // `--log-format` has no `LogConfig::complete` slot (Go has no
        // completion for it either), so it keeps the raw write-through.
        let mut cfg = crate::config::ServerConfig::default();
        cfg.log.format = "json".to_string();
        let args = parse_frps(&["--log-format", ""]).unwrap();
        args.override_server_config(&mut cfg);
        // The real order (`frps/src/main.rs`): override first, then Go's completion.
        cfg.complete();
        assert_eq!(
            cfg.log.format, "",
            "--log-format keeps the raw write-through (no zero-value filter)"
        );

        // A negative `--log-max-days` is explicit on Go too
        // (`util.EmptyOr(-1, 3)` is `-1`) and must pass through: only the zero
        // value is filtered. The `=` spelling below is a property of the
        // raw-argv helpers (`parse_frps`, `parse_frps_run` and the other
        // test-local `run_inner` call sites), not of the binaries: they hand
        // tokens straight to `run_inner`, so bpaf sees them raw and refuses the
        // space form — measured, "`--log-max-days` requires an argument DAYS,
        // got a flag -1, try `--log-max-days=-1` to use it as an argument". The
        // binaries accept both spellings, because `prepared_cli_argv` runs
        // `attach_flag_shaped_values`, which hands a `-`-shaped next token to
        // any listed value-taking long flag before bpaf sees it
        // (`VALUE_TAKING_LONG_FLAGS`; see `claims_the_next_token`). No real entry
        // point reaches the raw path: the two production paths pass
        // `prepared_cli_argv` output into `run_cli`. Measured on the built
        // binary: `frps --log-max-days -1` and `frps --log-max-days=-1` both
        // start the listener and both leave a five-day-old rotation file alive
        // (`-1` disables cleanup), and `frps --log-max-days -x` fails with
        // "couldn't parse `-x`: invalid digit found in string" — the token did
        // arrive as the value.
        let mut cfg = crate::config::ServerConfig::default();
        cfg.log.max_days = 5;
        let args = parse_frps(&["--log-max-days=-1"]).unwrap();
        args.override_server_config(&mut cfg);
        // The real order (`frps/src/main.rs`): override first, then Go's completion.
        cfg.complete();
        assert_eq!(cfg.log.max_days, -1, "only the zero value is filtered");
    }

    #[test]
    fn config_file_precedence_go_parity() {
        // Audit task 9 finding 5: with an explicit `-c` (or --config-dir)
        // the file is authoritative — CLI overrides are disabled, matching
        // Go frp v0.70.1 (root.go: flags only apply when cfgFile == "").
        let no_c = parse_frps(&[]).unwrap();
        assert_eq!(no_c.config_path(), "frps.toml");
        assert!(no_c.cli_overrides_enabled());

        let with_c = parse_frps(&["-c", "/etc/frp/frps.toml"]).unwrap();
        assert_eq!(with_c.config_path(), "/etc/frp/frps.toml");
        assert!(!with_c.cli_overrides_enabled());

        let with_dir = parse_frps(&["--config-dir", "/etc/frp/conf.d"]).unwrap();
        assert!(!with_dir.cli_overrides_enabled());
    }

    // ── frpc stop / --api-timeout ───────────────────────────────────────

    /// Parse `argv` (a whole admin-subcommand invocation) and return its
    /// `--api-timeout`, so a grammar case can be pinned on all three
    /// subcommands that must carry the flag.
    fn admin_api_timeout(argv: &[&str]) -> Duration {
        match argv[0] {
            "reload" => parse_frpc_reload(argv).unwrap().api_timeout,
            "status" => parse_frpc_status(argv).unwrap().api_timeout,
            "stop" => parse_frpc_stop(argv).unwrap().api_timeout,
            other => panic!("not an admin subcommand: {other}"),
        }
    }

    #[test]
    fn api_timeout_defaults_to_go_30s() {
        // Go frp v0.71.0 `var adminAPITimeout = 30 * time.Second`
        // (cmd/frpc/sub/admin.go:32); absent flag → 30 s. Checked on all three
        // subcommands because Go registers the default per subcommand.
        assert_eq!(DEFAULT_ADMIN_API_TIMEOUT, Duration::from_secs(30));
        assert_eq!(
            parse_frpc_reload(&["reload"]).unwrap().api_timeout,
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_frpc_status(&["status"]).unwrap().api_timeout,
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_frpc_stop(&["stop"]).unwrap().api_timeout,
            Duration::from_secs(30)
        );
    }

    #[test]
    fn api_timeout_parses_go_duration_grammar() {
        // Every value on the left was measured *accepted* by Go v0.71.0
        // (`frpc stop --api-timeout=<v> -c frpc.toml` with a refused admin
        // port); the right-hand side is `time.ParseDuration`'s value. Run on
        // reload/status/stop so the grammar cannot be wired to one command.
        let cases: [(&str, Duration); 15] = [
            ("1m", Duration::from_secs(60)),
            ("500ms", Duration::from_millis(500)),
            ("1h2m3.5s", Duration::from_millis(3_723_500)),
            ("1s500ms", Duration::from_millis(1_500)),
            ("1m0s", Duration::from_secs(60)),
            ("1.5h", Duration::from_secs(5_400)),
            (".5s", Duration::from_millis(500)),
            ("+1s", Duration::from_secs(1)),
            ("100us", Duration::from_micros(100)),
            ("1µs", Duration::from_micros(1)),
            ("1μs", Duration::from_micros(1)),
            ("0", Duration::ZERO),
            ("0s", Duration::ZERO),
            ("-1s", Duration::ZERO),
            (
                "2562047h47m16.854775807s",
                Duration::from_nanos(i64::MAX as u64),
            ),
        ];
        for command in ["reload", "status", "stop"] {
            for (text, expected) in cases {
                let flag = format!("--api-timeout={text}");
                assert_eq!(
                    admin_api_timeout(&[command, &flag]),
                    expected,
                    "{command} {flag}"
                );
            }
        }
        // `-1s` reaches the CLI as ZERO because a `Duration` cannot be
        // negative and the consumer only needs "deadline already past"
        // (see `parse_go_duration`).
        assert_eq!(parse_go_duration("-1s".into()).unwrap(), Duration::ZERO);
    }

    #[test]
    fn api_timeout_rejects_what_go_rejects() {
        // Measured rejected by Go v0.71.0, exit 1, message + usage on stderr:
        // `1` → `time: missing unit in duration "1"`; `abc`/`Inf` →
        // `time: invalid duration "…"`; `1d`/`1S`/`1Ms`/`1e3s` → `time: unknown
        // unit "…" in duration "…"`; `2562048h` and a 21-digit hour count →
        // `time: invalid duration "…"` (overflow).
        for text in [
            "1",
            "abc",
            "1d",
            "1S",
            "1Ms",
            "1e3s",
            "Inf",
            "2562048h",
            "999999999999999999999h",
            "",
        ] {
            assert!(parse_go_duration(text.into()).is_err(), "{text:?}");
            for command in ["reload", "status", "stop"] {
                for prefix in ["--api-timeout", "--api_timeout"] {
                    let flag = format!("{prefix}={text}");
                    assert!(
                        frpc_parser()
                            .to_options()
                            .run_inner(&[command, &flag][..])
                            .is_err(),
                        "{command} {flag} must be rejected"
                    );
                }
            }
        }
        // The two wordings the brief pins verbatim.
        assert_eq!(
            parse_go_duration("1".into()).unwrap_err(),
            "time: missing unit in duration \"1\""
        );
        assert_eq!(
            parse_go_duration("abc".into()).unwrap_err(),
            "time: invalid duration \"abc\""
        );
    }

    #[test]
    fn api_timeout_rejects_go_uint64_wrap_where_go_accepts_zero() {
        // The one divergence a 420-value randomised differential sweep found:
        // Go accumulates the group total in a `uint64` (`d += v`) and only
        // checks `d > 1<<63`, so two 2^63 ns groups wrap to 0 and Go *accepts*
        // this input as 0 ns — measured on the v0.71.0 binary, `frpc stop
        // --api-timeout=9223372036854775808ns9223372036854775808ns` prints
        // `context deadline exceeded`, exit 1. frp-rs uses checked arithmetic
        // and rejects it: stricter than Go, and never a panic.
        let wrapped = "9223372036854775808ns9223372036854775808ns";
        assert_eq!(
            parse_go_duration(wrapped.into()).unwrap_err(),
            "time: invalid duration \"9223372036854775808ns9223372036854775808ns\""
        );
        for command in ["reload", "status", "stop"] {
            let flag = format!("--api-timeout={wrapped}");
            assert!(
                frpc_parser()
                    .to_options()
                    .run_inner(&[command, &flag][..])
                    .is_err(),
                "{command} {flag} must be rejected"
            );
        }
    }

    #[test]
    fn api_timeout_is_not_accepted_outside_the_three_admin_commands() {
        // Go registers `--api-timeout` per subcommand inside `init()`'s loop
        // (cmd/frpc/sub/admin.go:45-49, the DurationVar at :47); measured on
        // v0.71.0, `frpc verify --api-timeout=1s` → `Error: unknown flag:
        // --api-timeout`, exit 1. Same for the underscore spelling.
        let tcp: [&str; 5] = ["tcp", "--local-port", "1", "--remote-port", "2"];
        assert!(
            frpc_parser().to_options().run_inner(&tcp[..]).is_ok(),
            "control: the tcp invocation without the flag must parse"
        );
        for argv in [
            &["--api-timeout", "1s"][..],
            &["verify", "--api-timeout=1s", "-c", "x.toml"][..],
            &["verify", "--api_timeout=1s", "-c", "x.toml"][..],
            &[
                "tcp",
                "--api-timeout=1s",
                "--local-port",
                "1",
                "--remote-port",
                "2",
            ][..],
        ] {
            assert!(
                frpc_parser().to_options().run_inner(argv).is_err(),
                "{argv:?} must be rejected"
            );
        }
    }

    #[test]
    fn api_timeout_underscore_spelling_matches_go() {
        // Go v0.71.0 accepts `--api_timeout` on these three subcommands as it
        // accepts every hyphen spelling (measured: `frpc stop
        // --api_timeout=abc` fails on `--api-timeout`, so the alias reaches the
        // same flag, while `--api_timeoutt` is `unknown flag`;
        // `docs/deployment.md` carries the mechanism). frp-rs registers both
        // spellings here and must enforce the same grammar on each.
        assert_eq!(
            admin_api_timeout(&["stop", "--api_timeout=500ms"]),
            Duration::from_millis(500)
        );
        assert_eq!(
            admin_api_timeout(&["reload", "--api_timeout", "2s"]),
            Duration::from_secs(2)
        );
        assert!(
            parse_frpc_status(&["status", "--api_timeout=abc"]).is_err(),
            "the alias must enforce the same grammar as the hyphen spelling"
        );
    }

    #[test]
    fn stop_accepts_the_shared_admin_flags_and_defaults_strict() {
        let args = parse_frpc_stop(&[
            "stop",
            "-c",
            "x.toml",
            "--strict-config=false",
            "--admin-addr",
            "10.0.0.1",
            "--admin-port",
            "7401",
            "--admin-user",
            "u",
            "--admin-pwd",
            "p",
        ])
        .unwrap();
        assert_eq!(args.config.as_deref(), Some("x.toml"));
        assert!(!args.strict_config);
        assert_eq!(args.admin_addr.as_deref(), Some("10.0.0.1"));
        assert_eq!(args.admin_port, Some(7401));
        assert_eq!(args.admin_user.as_deref(), Some("u"));
        assert_eq!(args.admin_pwd.as_deref(), Some("p"));
        assert_eq!(args.api_timeout, DEFAULT_ADMIN_API_TIMEOUT);
        // `--strict-config` is a persistent rootCmd flag (default true), so
        // stop inherits run-mode semantics like reload/status.
        assert!(parse_frpc_stop(&["stop"]).unwrap().strict_config);
        assert!(
            parse_frpc_stop(&["stop", "--strict_config"])
                .unwrap()
                .strict_config
        );
        assert!(
            !parse_frpc_stop(&["stop", "--strict_config", "false"])
                .unwrap()
                .strict_config
        );
    }

    #[test]
    fn strict_config_help_text_states_the_extension() {
        // The done-when for `TODO.md:3366` requires the divergence stated in
        // the flag's **help text**, not only in `docs/`.
        //
        // The two entries must be pinned **separately**, because the rendered
        // help contains `--strict-config=<bool>` in both: a deletion of just
        // the value-form `.help()` leaves a fragment-only assertion green (that
        // mutant was run and did pass against the first version of this test).
        // So each entry is asserted twice:
        //
        // 1. the parser still uses each help const — the rendered, whitespace-
        //    squashed help must contain the squashed const (this catches a
        //    deleted or swapped `.help()`);
        // 2. the const still *means* what it must — asserted against literals
        //    written here, deliberately **not** derived from the consts, so a
        //    rewritten (e.g. inverted) const fails even though it still renders.
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let value_help = squash(STRICT_CONFIG_VALUE_HELP);
        let switch_help = squash(STRICT_CONFIG_SWITCH_HELP);

        // 2. Meaning, per entry, with independent literals.
        assert!(
            value_help.contains("Strict config parsing mode: true or false."),
            "the value entry must keep its own meaning: {value_help:?}"
        );
        assert!(
            value_help.contains("The Go-faithful value spelling is --strict-config=<bool>"),
            "the value entry must name the Go-faithful spelling: {value_help:?}"
        );
        assert!(
            switch_help.contains("The Go-faithful spellings are this bare flag (=true)"),
            "the bare entry must state what the bare flag means: {switch_help:?}"
        );
        // One contiguous clause: an inverted sentence ("…the only Go-faithful
        // one… Go's pflag does not differ here") cannot contain it.
        assert!(
            switch_help.contains(
                "frp-rs additionally consumes a space-separated --strict-config <bool> as the \
                 value, which Go's pflag does not"
            ),
            "the bare entry must state the extension and that Go's pflag does not consume it: \
             {switch_help:?}"
        );
        assert!(
            !switch_help.contains("Go-faithful spelling is the space-separated"),
            "the space form must never be described as the Go-faithful spelling: {switch_help:?}"
        );
        assert_ne!(
            value_help, switch_help,
            "the two entries must not be the same string"
        );

        // 1. Every parser renders both entries.
        let cases: [(&str, bool, &str); 6] = [
            ("frps", true, "--help"),
            ("frpc run", false, "--help"),
            ("frpc verify", false, "verify --help"),
            ("frpc reload", false, "reload --help"),
            ("frpc status", false, "status --help"),
            ("frpc stop", false, "stop --help"),
        ];
        for (label, is_frps, argv) in cases {
            let argv: Vec<&str> = argv.split(' ').collect();
            let failure = if is_frps {
                frps_args().to_options().run_inner(&argv[..]).map(|_| ())
            } else {
                frpc_parser().to_options().run_inner(&argv[..]).map(|_| ())
            }
            .expect_err("--help is reported as a ParseFailure");
            let help = squash(&failure.unwrap_stdout());
            assert!(help.contains(&value_help), "{label} value entry: {help}");
            assert!(help.contains(&switch_help), "{label} switch entry: {help}");
        }
    }

    #[test]
    fn strict_config_warning_detection_matches_the_consumed_shape() {
        // The warning is keyed off argv, so the detection must mirror bpaf
        // exactly: only a `--strict-config`/`--strict_config` token followed by
        // a *consumed* bool value counts. `parse_frps_args`/`parse_frpc_args`
        // additionally warn only after a successful parse, so a candidate shape
        // whose parse then fails stays silent.
        let warned = |args: &[&str]| {
            let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
            strict_config_space_form_used(&argv)
        };

        // The extension: a following token that is a bool in Go's ParseBool
        // grammar, both spellings, several value shapes.
        for args in [
            &["frpc", "verify", "--strict-config", "false", "-c", "x.toml"][..],
            &["frpc", "verify", "--strict-config", "true", "-c", "x.toml"][..],
            &["frpc", "reload", "--strict_config", "0"][..],
            &["frpc", "status", "--strict-config", "1"][..],
            &["frpc", "run", "--strict-config", "TRUE"][..],
            &["frps", "--strict-config", "False", "-c", "frps.toml"][..],
        ] {
            assert!(warned(args), "{args:?} must be detected as the extension");
        }

        // Everything Go-faithful or non-consuming stays silent.
        for args in [
            // `=` spelling: one token, so the equality test never matches.
            &["frpc", "verify", "--strict-config=false", "-c", "x.toml"][..],
            &["frpc", "verify", "--strict_config=true", "-c", "x.toml"][..],
            // bare switch followed by another flag (bpaf never takes a
            // `-`-prefixed token as a value) …
            &["frps", "--strict-config", "-c", "frps.toml"][..],
            // … or at the end of argv.
            &["frps", "--strict-config"][..],
            &["frpc", "stop", "--strict_config"][..],
            // a non-bool token: the parse fails there, so nothing is consumed
            // and the process exits before a warning could matter.
            &["frpc", "verify", "--strict-config", "foo", "-c", "x.toml"][..],
            &["frpc", "verify", "--strict-config", "", "-c", "x.toml"][..],
            &["frpc", "verify", "--strict-config", "-1", "-c", "x.toml"][..],
            // `=` spelling with a bool-looking *next* token: the next token is
            // not consumed by `--strict-config` at all.
            &["frpc", "verify", "--strict-config=false", "false"][..],
        ] {
            assert!(!warned(args), "{args:?} must not warn");
        }

        // Documented caveat: detection is argv-local, so a `--strict-config`
        // that is really another flag's value does match here. It cannot
        // produce a warning, because that argv fails to parse (`-c` refuses a
        // `-`-prefixed value) and the entry points warn only after `run()`
        // returned — i.e. the successful-parse gate, not the scan, is what
        // keeps the warning honest.
        assert!(warned(&["frpc", "-c", "--strict-config", "false"]));
    }

    // ── `--flag=<bool>` on every Go-parity bool flag ──────────────────────
    //
    // Go registers these as pflag bools, which accept the bare `--flag`, and
    // `--flag=true` / `--flag=false` parsed by `strconv.ParseBool`. bpaf's
    // `.switch()` accepted only the bare form, so `frps --tls-only=false -c
    // <valid config>` started on Go (rc 124 under a bounded runner) and exited
    // 1 here (`TODO.md:3498`). The rows below are the parser half; the
    // real-binary half is `frps/tests/cli_exit_codes.rs` and
    // `frpc/tests/cli_exit_codes.rs`.

    /// Every bool flag the two binaries register, as
    /// `(site label, canonical long name, underscore alias)`.
    ///
    /// The list is the sweep's own answer to "how many are there" — ten flags
    /// over four parser surfaces — and every row is exercised below, so a new
    /// `.switch()` that is not routed through the shared parser has to be
    /// added here too.
    const GO_BOOL_SITES: [(&str, &str, Option<&str>); 10] = [
        ("frps --tls-only", "--tls-only", Some("--tls_only")),
        (
            "frps --enable-prometheus",
            "--enable-prometheus",
            Some("--enable_prometheus"),
        ),
        (
            "frps --disable-log-color",
            "--disable-log-color",
            Some("--disable_log_color"),
        ),
        (
            "frps --dashboard-tls-mode",
            "--dashboard-tls-mode",
            Some("--dashboard_tls_mode"),
        ),
        ("frps --version", "--version", None),
        (
            "frpc --disable-log-color",
            "--disable-log-color",
            Some("--disable_log_color"),
        ),
        ("frpc --version", "--version", None),
        ("frpc tcp --ue", "--ue", Some("--use_encryption")),
        ("frpc tcp --uc", "--uc", Some("--use_compression")),
        ("frpc status --json", "--json", None),
    ];

    /// Parse the flag under test on its own surface: the required positional
    /// arguments of `frpc tcp`/`frpc status` are supplied, and the flag argv is
    /// appended.
    fn parse_site(site: &str, flag_argv: &[&str]) -> Result<bool, bpaf::ParseFailure> {
        let base: &[&str] = match site {
            "frpc tcp --ue" | "frpc tcp --uc" => {
                &["tcp", "--local-port", "1", "--remote-port", "2"]
            }
            "frpc status --json" => &["status"],
            _ => &[],
        };
        let argv: Vec<&str> = base
            .iter()
            .copied()
            .chain(flag_argv.iter().copied())
            .collect();
        match site {
            "frps --tls-only" => parse_frps(&argv).map(|a| a.tls_only),
            "frps --enable-prometheus" => parse_frps(&argv).map(|a| a.enable_prometheus),
            "frps --disable-log-color" => parse_frps(&argv).map(|a| a.disable_log_color),
            "frps --dashboard-tls-mode" => parse_frps(&argv).map(|a| a.dashboard_tls_mode),
            "frps --version" => parse_frps(&argv).map(|a| a.show_version),
            "frpc --disable-log-color" => parse_frpc_run(&argv).map(|a| a.disable_log_color),
            "frpc --version" => parse_frpc_run(&argv).map(|a| a.show_version),
            "frpc tcp --ue" => parse_frpc_tcp(&argv).map(|a| a.use_encryption),
            "frpc tcp --uc" => parse_frpc_tcp(&argv).map(|a| a.use_compression),
            "frpc status --json" => parse_frpc_status(&argv).map(|a| a.json),
            other => panic!("unknown site {other}"),
        }
    }

    #[test]
    fn every_go_bool_flag_accepts_the_pflag_value_spellings() {
        for (site, name, alias) in GO_BOOL_SITES {
            // Absent keeps `.switch()`'s default — this change adds spellings,
            // it does not move any default.
            assert!(
                !parse_site(site, &[]).unwrap(),
                "{site}: absent must stay false"
            );
            // Bare = true on every site (Go's pflag bool).
            assert!(parse_site(site, &[name]).unwrap(), "{site}: bare = true");
            // Go's `strconv.ParseBool` true/false spellings, verbatim.
            for value in ["true", "1", "t", "T", "TRUE", "True"] {
                let arg = format!("{name}={value}");
                assert!(
                    parse_site(site, &[&arg]).unwrap(),
                    "{site}: {arg} must parse as true"
                );
            }
            for value in ["false", "0", "f", "F", "FALSE", "False"] {
                let arg = format!("{name}={value}");
                assert!(
                    !parse_site(site, &[&arg]).unwrap(),
                    "{site}: {arg} must parse as false"
                );
            }
            // The underscore alias is the same pflag variable on Go and the
            // same parser branch here, so it must take the same values.
            if let Some(alias) = alias {
                let t = format!("{alias}=TRUE");
                let f = format!("{alias}=false");
                assert!(parse_site(site, &[&t]).unwrap(), "{site}: {t}");
                assert!(!parse_site(site, &[&f]).unwrap(), "{site}: {f}");
            }
        }
    }

    #[test]
    fn every_go_bool_flag_refuses_non_bool_values_and_the_space_form() {
        for (site, name, _) in GO_BOOL_SITES {
            // `--flag=foo` is Go's `invalid argument "foo" for "--flag" flag:
            // strconv.ParseBool: …`, exit 1; here bpaf backtracks and reports
            // the leftover value, which is the same message the switch sites
            // produced before. Both must exit 1 — the rc is the contract, the
            // message shape may differ.
            let bad = format!("{name}=foo");
            let err = parse_site(site, &[&bad])
                .expect_err("a non-bool value must be refused")
                .unwrap_stderr();
            assert!(
                err.contains("is not expected in this context"),
                "{site}: {bad} must fail as a leftover token, got {err}"
            );
            // The empty attached value is a value Go also refuses
            // (`strconv.ParseBool: parsing "": invalid syntax`).
            let empty = format!("{name}=");
            assert!(parse_site(site, &[&empty]).is_err(), "{site}: {empty}");
            // The space-separated form is *not* consumed: `.adjacent()` keeps
            // this byte-identical to the pre-change `.switch()` refusal, which
            // is also what Go's root commands do with the stray token
            // (`Error: unknown command "false" for "frps"`, rc 1). The
            // per-command rows where Go does *not* refuse it are recorded in
            // `docs/developing.md`, not silently matched here.
            assert!(
                parse_site(site, &[name, "false"]).is_err(),
                "{site}: `{name} false` must stay refused (Go does not consume \
                 the token either)"
            );
        }
    }

    #[test]
    fn every_go_bool_flag_help_states_its_own_spelling() {
        // `help` must name the spelling *of the flag it is attached to*, and
        // the claim must match what Go actually registers. The expected lines
        // are written out here as independent literals (not read back from the
        // macro), so a deleted `.help()`, a help naming another flag, or a
        // claim that Go has a bool where it has a string all fail.
        let squash = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let help_of = |site: &str| -> String {
            let argv: Vec<&str> = match site {
                "frps" => vec!["--help"],
                "frpc" => vec!["--help"],
                "frpc tcp" => vec!["tcp", "--help"],
                "frpc status" => vec!["status", "--help"],
                other => panic!("unknown surface {other}"),
            };
            let failure = if site == "frps" {
                frps_args().to_options().run_inner(&argv[..]).map(|_| ())
            } else {
                frpc_parser().to_options().run_inner(&argv[..]).map(|_| ())
            }
            .expect_err("--help is reported as a ParseFailure");
            squash(&failure.unwrap_stdout())
        };

        // (surface, long name, meaning, how the value entry must describe Go)
        let rows: [(&str, &str, &str, &str); 10] = [
            ("frps", "--tls-only", "Frps TLS only", "go-bool"),
            (
                "frps",
                "--enable-prometheus",
                "Enable prometheus dashboard",
                "go-bool",
            ),
            (
                "frps",
                "--disable-log-color",
                "Disable log color in console",
                "go-bool",
            ),
            (
                "frps",
                "--dashboard-tls-mode",
                "Enable dashboard TLS mode",
                "go-string",
            ),
            ("frps", "--version", "Version of frps", "go-bool"),
            (
                "frpc",
                "--disable-log-color",
                "Disable log color in console",
                "go-bool",
            ),
            ("frpc", "--version", "Version of frpc", "go-bool"),
            ("frpc tcp", "--ue", "use encryption", "go-bool"),
            ("frpc tcp", "--uc", "use compression", "go-bool"),
            (
                "frpc status",
                "--json",
                "Output the status as JSON",
                "rs-only",
            ),
        ];

        for (surface, name, meaning, claim) in rows {
            let help = help_of(surface);
            let (value_help, switch_help) = match claim {
                // Go registers a pflag bool under this name.
                "go-bool" => (
                    format!("{meaning}. The Go-faithful value spelling is {name}=<bool>"),
                    format!("{meaning} (bare form = true)"),
                ),
                // Go registers the name, but as a *string* flag: the help must
                // say so instead of implying a Go bool.
                "go-string" => (
                    format!(
                        "{meaning}. frp-rs value spelling: {name}=<bool>; Go's {name} is a \
                         string flag and accepts any value there"
                    ),
                    format!(
                        "{meaning} (bare form = true); Go's {name} is a string flag and \
                         consumes the next token"
                    ),
                ),
                // Go has no flag of this name at all.
                "rs-only" => (
                    format!(
                        "{meaning}. {name}=<bool> is an frp-rs extension: Go registers no {name}"
                    ),
                    format!("{meaning} (bare form = true)"),
                ),
                other => panic!("unknown claim {other}"),
            };
            assert!(
                help.contains(&value_help),
                "{surface} must render the {name}=BOOL entry: {value_help:?} not in {help}"
            );
            assert!(
                help.contains(&switch_help),
                "{surface} must render the {name} switch entry: {switch_help:?} not in {help}"
            );
            assert_ne!(value_help, switch_help);
        }

        // The usage line's value alternative is part of the rendered help and is
        // quoted as a carrier in `docs/developing.md`; pin the spelling for the
        // one flag that also has a short, so a future parser change cannot
        // silently re-render `-v=BOOL` (or drop the alternative) while the
        // per-entry assertions above still pass. Spaces are removed first
        // because the usage line wraps at the output width.
        let usage: String = help_of("frps").split_whitespace().collect();
        assert!(
            usage.contains("(--version=BOOL|[-v])"),
            "the usage line must render the long value spelling plus the short: {usage}"
        );
    }

    /// Every proxy surface takes Go's `--ue`/`--uc` as the primary spelling and
    /// keeps frp-rs's two older spellings on the same parser branch.
    ///
    /// Go registers `use-encryption`/`use-compression` on **no** command — its
    /// pflag names are `uc`/`ue` (measured on the v0.71.0 binary) — so the older
    /// names are frp-rs extensions, accepted so existing command lines keep
    /// working. This test is what holds the alias half of that decision: a later
    /// edit that dropped an alias would otherwise leave the whole suite green.
    ///
    /// Both frp-rs spellings are parsed **per surface** here, hyphen included:
    /// `GO_BOOL_SITES` carries only the underscore form on `frpc tcp`, so leaving
    /// `--use-compression` to that table would let any surface drop the hyphen
    /// alias with the whole suite still green.
    #[test]
    fn every_proxy_surface_accepts_go_bool_names_and_their_frp_rs_aliases() {
        const SURFACES: [(&str, &[&str]); 8] = [
            ("tcp", &["--local-port", "1", "--remote-port", "2"]),
            ("udp", &["--local-port", "1", "--remote-port", "2"]),
            (
                "http",
                &["--local-port", "1", "--custom-domain", "h.example"],
            ),
            (
                "https",
                &["--local-port", "1", "--custom-domain", "h.example"],
            ),
            ("stcp", &["--local-port", "1", "--sk", "s"]),
            ("xtcp", &["--local-port", "1", "--sk", "s"]),
            ("sudp", &["--local-port", "1", "--remote-port", "1"]),
            ("tcpmux", &["--local-port", "1"]),
        ];
        // `(argv spelling, read the encryption field, read the compression field)`
        let read = |command: &FrpcCmd| -> (bool, bool) {
            match command {
                FrpcCmd::Tcp(a) => (a.use_encryption, a.use_compression),
                FrpcCmd::Udp(a) => (a.use_encryption, a.use_compression),
                FrpcCmd::Http(a) => (a.use_encryption, a.use_compression),
                FrpcCmd::Https(a) => (a.use_encryption, a.use_compression),
                FrpcCmd::Stcp(a) => (a.use_encryption, a.use_compression),
                FrpcCmd::Xtcp(a) => (a.use_encryption, a.use_compression),
                FrpcCmd::Sudp(a) => (a.use_encryption, a.use_compression),
                FrpcCmd::Tcpmux(a) => (a.use_encryption, a.use_compression),
                other => panic!("expected a proxy command, got {other:?}"),
            }
        };
        for (surface, required) in SURFACES {
            let mut base: Vec<&str> = vec![surface];
            base.extend_from_slice(required);
            for (flag, expect_encryption) in [
                ("--ue", true),
                ("--use-encryption", true),
                ("--use_encryption", true),
                ("--uc", false),
                ("--use-compression", false),
                ("--use_compression", false),
            ] {
                let mut argv = base.clone();
                argv.push(flag);
                let command = parse_frpc_proxy(&argv)
                    .unwrap_or_else(|e| panic!("frpc {surface} {flag}: {e:?}"));
                let (encryption, compression) = read(&command);
                assert_eq!(
                    encryption, expect_encryption,
                    "frpc {surface} {flag} must set use_encryption={expect_encryption}"
                );
                assert_eq!(
                    compression, !expect_encryption,
                    "frpc {surface} {flag} must only set its own field"
                );
            }
        }
    }

    #[test]
    fn every_go_bool_flag_rejects_a_repeated_flag() {
        // Recorded divergence, not a claim of parity: Go's pflag is last-wins
        // (`frps --tls-only --tls-only=false` → rc 124, `… =false … --tls-only`
        // → rc 124 too, measured), while every one of these flags refuses the
        // second occurrence with rc 1 — the same repetition refusal
        // `--strict-config` already has (`docs/developing.md`). Pinned so the
        // behaviour cannot change silently in either direction.
        for (site, name, _) in GO_BOOL_SITES {
            let bare_then_false = [name, &format!("{name}=false")];
            let false_then_bare = [&format!("{name}=false"), name];
            for argv in [bare_then_false.as_slice(), false_then_bare.as_slice()] {
                let result = parse_site(site, argv);
                assert!(
                    result.is_err(),
                    "{site}: repeated {argv:?} must stay refused (Go is last-wins there)"
                );
            }
        }
    }

    /// The argv rewrite the entry points apply before bpaf sees argv. `-v`
    /// is the only bool short either binary registers, so this is the whole
    /// rule: `-v=<bool>` becomes `--version=<bool>` (pflag treats them as one
    /// variable), and everything else — the bare `-v`, a shorthand cluster
    /// (`-vtrue`), an `=`-spelling of a *value-taking* short (`-c=x`), a
    /// non-UTF-8 token — is passed through untouched for bpaf to parse.
    #[test]
    fn bool_short_equals_spelling_expands_to_the_long_form_only() {
        let expand = |args: &[&str]| -> Vec<String> {
            expand_bool_short_value_form(args.iter().map(OsString::from).collect())
                .into_iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect()
        };

        // pflag's shorthand `=` spelling: rewritten, value and all.
        assert_eq!(expand(&["-v=false"]), ["--version=false"]);
        assert_eq!(expand(&["-v=TRUE"]), ["--version=TRUE"]);
        assert_eq!(expand(&["-v="]), ["--version="]);
        assert_eq!(
            expand(&["-c", "x.toml", "-v=false"]),
            ["-c", "x.toml", "--version=false"]
        );

        // Everything else is exactly what bpaf had before.
        for argv in [
            &["-v"][..],
            &["-vtrue"][..],
            &["-vh"][..],
            &["-vfoo"][..],
            &["-v0"][..],
            &["--version=false"][..],
            &["--version"][..],
            // `-c=x` / `-t=v` are value-taking shorts and already parse their
            // `=` spelling through bpaf — rewriting them would be a new rule.
            &["-c=x.toml"][..],
            &["-t=v"][..],
            &["-vp7000"][..],
        ] {
            assert_eq!(
                expand(argv),
                argv.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                "{argv:?} must pass through untouched"
            );
        }

        // A non-UTF-8 token cannot be inspected, so it must not be dropped or
        // mangled (unix is where such an argv can exist at all).
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let raw = OsString::from_vec(vec![b'-', b'v', b'=', 0xff]);
            let out = expand_bool_short_value_form(vec![raw.clone()]);
            assert_eq!(out, vec![raw]);
        }

        // Nothing after the first `--` is a flag, so nothing there is rewritten
        // either: a rewritten token would surface in a rejection message as
        // `--version=false` where the user typed `-v=false`. Measured on the
        // binary, `frps -- -v=false` is rc 1 and names `-v=false`, as the base
        // head did; only the token *after* the separator is skipped.
        assert_eq!(
            expand(&["--", "-v=false"]),
            ["--", "-v=false"],
            "the separator must stop the rewrite"
        );
        assert_eq!(
            expand(&["-v=false", "--", "-v=false"]),
            ["--version=false", "--", "-v=false"],
            "before the separator is still rewritten, after it is not"
        );
    }

    #[test]
    fn strict_config_warning_text_is_the_documented_line() {
        // Pin the exact line users see (and scripts may match), including the
        // Go-faithful spelling it recommends.
        assert_eq!(
            STRICT_CONFIG_SPACE_FORM_WARNING,
            "warning: --strict-config <bool> is an frp-rs extension; Go's pflag does not consume \
             the token and stays strict. Use --strict-config=<bool> for identical behaviour."
        );
    }

    #[test]
    fn stop_help_is_go_short_text() {
        // Go v0.71.0 `cmd/frpc/sub/admin.go:42` registers the short text
        // `Stop the running frpc`, and `frpc --help` lists it under
        // `Available Commands`. bpaf renders the per-command `.help()` string
        // in the parent's command list, which is where frp-rs prints it:
        // `frpc --help` shows `stop` with this text.
        let failure = frpc_parser()
            .to_options()
            .run_inner(&["--help"][..])
            .expect_err("--help is reported as a ParseFailure");
        match failure {
            bpaf::ParseFailure::Stdout(doc, _) => {
                let text = doc.to_string();
                assert!(text.contains("Stop the running frpc"), "help={text}");
            }
            other => panic!("expected help on stdout, got {other:?}"),
        }
    }

    // ── `-c`/`--config` is last-wins, like Go's pflag StringVarP ──────────
    //
    // Go registers `-c` with `StringVarP` inside `func init()`
    // (`cmd/frpc/sub/root.go`), so a repeated flag is never an error and the
    // last value wins. Measured on Go v0.71.0 darwin/arm64:
    // `frpc status -c noweb.toml -c p7499.toml` dials `127.0.0.1:7499` and
    // `-c p7499.toml -c noweb.toml` prints Go's port refusal (see
    // `frpc/tests/cli_inputs.rs` for the end-to-end form). bpaf failed the
    // second occurrence with
    // ``argument `-c` cannot be used multiple times in this context`` before
    // every frpc parser was routed through `config_arg`.

    #[test]
    fn run_mode_config_is_last_wins() {
        let args = parse_frpc_run(&["-c", "a.toml", "-c", "b.toml"]).unwrap();
        assert_eq!(args.config, "b.toml");
        // Mixed spellings are the same pflag variable.
        let args = parse_frpc_run(&["--config", "a.toml", "-c", "b.toml"]).unwrap();
        assert_eq!(args.config, "b.toml");
        // Three occurrences: still the last.
        let args = parse_frpc_run(&["-c", "a.toml", "-c", "b.toml", "-c", "c.toml"]).unwrap();
        assert_eq!(args.config, "c.toml");
        // Absent keeps the frp-rs default; one occurrence is unchanged.
        assert_eq!(parse_frpc_run(&[]).unwrap().config, "frpc.toml");
        assert_eq!(
            parse_frpc_run(&["-c", "only.toml"]).unwrap().config,
            "only.toml"
        );
        // The flag still needs a value.
        assert!(parse_frpc_run(&["-c"]).is_err());
    }

    #[test]
    fn verify_config_is_last_wins_and_still_required() {
        let args = parse_frpc_verify(&["verify", "-c", "a.toml", "-c", "b.toml"]).unwrap();
        assert_eq!(args.config, "b.toml");
        assert_eq!(
            parse_frpc_verify(&["verify", "-c", "only.toml"])
                .unwrap()
                .config,
            "only.toml"
        );
        // No fallback here: `verify` refuses a missing `-c`, as before.
        assert!(parse_frpc_verify(&["verify"]).is_err());
        assert!(parse_frpc_verify(&["verify", "-c"]).is_err());
    }

    #[test]
    fn admin_config_is_last_wins_and_still_optional() {
        // The subcommand name is part of the argv: without it bpaf falls back
        // to run mode (the last branch of the `construct!` alternation).
        let args = parse_frpc_reload(&["reload", "-c", "a.toml", "-c", "b.toml"]).unwrap();
        assert_eq!(args.config.as_deref(), Some("b.toml"));
        let args = parse_frpc_status(&["status", "-c", "a.toml", "-c", "b.toml"]).unwrap();
        assert_eq!(args.config.as_deref(), Some("b.toml"));
        let args = parse_frpc_stop(&["stop", "-c", "a.toml", "-c", "b.toml"]).unwrap();
        assert_eq!(args.config.as_deref(), Some("b.toml"));
        // Absent stays `None` for all three (the frp-rs `127.0.0.1:7400`
        // default path, a recorded divergence).
        assert_eq!(parse_frpc_reload(&["reload"]).unwrap().config, None);
        assert_eq!(parse_frpc_status(&["status"]).unwrap().config, None);
        assert_eq!(parse_frpc_stop(&["stop"]).unwrap().config, None);
        assert!(parse_frpc_reload(&["reload", "-c"]).is_err());
        assert!(parse_frpc_status(&["status", "-c"]).is_err());
        assert!(parse_frpc_stop(&["stop", "-c"]).is_err());
    }

    #[test]
    fn config_help_says_the_flag_may_repeat() {
        // bpaf renders `last()` as a repeatable option (`-c=FILE...`), which is
        // accurate for pflag. Pinned so the help cannot drift back to a
        // single-use spelling while the parser stays last-wins.
        let failure = frpc_parser()
            .to_options()
            .run_inner(&["--help"][..])
            .expect_err("--help is reported as a ParseFailure");
        match failure {
            bpaf::ParseFailure::Stdout(doc, _) => {
                let text = doc.to_string();
                assert!(text.contains("[-c=FILE...]"), "help={text}");
            }
            other => panic!("expected help on stdout, got {other:?}"),
        }
        let failure = frpc_parser()
            .to_options()
            .run_inner(&["verify", "--help"][..])
            .expect_err("verify --help is reported as a ParseFailure");
        match failure {
            bpaf::ParseFailure::Stdout(doc, _) => {
                let text = doc.to_string();
                assert!(text.contains("verify -c=FILE..."), "help={text}");
            }
            other => panic!("expected help on stdout, got {other:?}"),
        }
    }

    // ── the persistent rootCmd flags, accepted and ignored everywhere ─────
    //
    // Go registers `-c/--config`, `--config-dir`, `--strict-config`,
    // `--allow-unsafe` and `-v/--version` on `rootCmd`
    // (`cmd/frpc/sub/root.go`, `func init()`), so pflag parses them for every
    // subcommand — `frpc tcp --help` lists all five under `Global Flags` —
    // while the single-proxy commands read none of them. Measured on Go
    // v0.71.0 darwin/arm64: with a fixed proxy name, every flag shape below
    // still reaches `try to connect to server...` and connects to the probe
    // port. The end-to-end form is pinned by
    // `frpc/tests/cli_persistent_flags.rs`.

    /// Each single-proxy command with its own required flags, without any
    /// persistent root flag. `--server-port` is added by the caller in the
    /// end-to-end test only.
    const SINGLE_PROXY_BASE: [(&str, &[&str]); 8] = [
        (
            "tcp",
            &[
                "--local-port",
                "5",
                "--remote-port",
                "6",
                "--proxy-name",
                "x",
            ],
        ),
        (
            "udp",
            &[
                "--local-port",
                "5",
                "--remote-port",
                "6",
                "--proxy-name",
                "x",
            ],
        ),
        (
            "http",
            &[
                "--local-port",
                "5",
                "--custom-domains",
                "example.com",
                "--proxy-name",
                "x",
            ],
        ),
        (
            "https",
            &[
                "--local-port",
                "5",
                "--custom-domains",
                "example.com",
                "--proxy-name",
                "x",
            ],
        ),
        ("stcp", &["--local-port", "5", "--sk", "s"]),
        ("xtcp", &["--local-port", "5", "--sk", "s"]),
        (
            "sudp",
            &[
                "--local-port",
                "5",
                "--remote-port",
                "6",
                "--proxy-name",
                "x",
            ],
        ),
        (
            "tcpmux",
            &["--local-port", "5", "--mux-port", "7", "--proxy-name", "x"],
        ),
    ];

    const ALL_FIVE_ROOT_FLAGS: [&str; 8] = [
        "-c",
        "missing.toml",
        "--config-dir",
        "cDir",
        "--strict-config=false",
        "--allow-unsafe",
        "TokenSourceExec",
        "--version",
    ];

    fn single_proxy_argv(cmd: &str, base: &[&str], extra: &[&str]) -> Vec<String> {
        let mut argv = vec![cmd.to_string()];
        argv.extend(base.iter().map(|s| s.to_string()));
        argv.extend(extra.iter().map(|s| s.to_string()));
        argv
    }

    #[test]
    fn every_single_proxy_command_accepts_the_five_persistent_root_flags() {
        for (cmd, base) in SINGLE_PROXY_BASE {
            let argv = single_proxy_argv(cmd, base, &ALL_FIVE_ROOT_FLAGS);
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            let parsed = frpc_parser().to_options().run_inner(&refs[..]);
            assert!(parsed.is_ok(), "{cmd} refused {argv:?}: {parsed:?}");
            assert!(
                !matches!(parsed.unwrap(), FrpcCmd::Run(_)),
                "{cmd} fell through to run mode"
            );
        }
    }

    #[test]
    fn tcp_config_flag_value_is_parsed_and_dropped() {
        // Go ignores the file on these commands: the proxy must start with
        // `-c` pointing at a path that does not exist, with the last of a
        // repeated pair, and with an empty value. Nothing here loads a file.
        let args = parse_frpc_tcp(&[
            "tcp",
            "--local-port",
            "5",
            "--remote-port",
            "6",
            "-c",
            "missing.toml",
        ])
        .unwrap();
        assert_eq!(args.local_port, 5);
        assert_eq!(args.remote_port, 6);
        let args = parse_frpc_tcp(&[
            "tcp",
            "--local-port",
            "5",
            "--remote-port",
            "6",
            "-c",
            "a.toml",
            "-c",
            "b.toml",
        ])
        .unwrap();
        assert_eq!(args.remote_port, 6);
        assert!(parse_frpc_tcp(&[
            "tcp",
            "--local-port",
            "5",
            "--remote-port",
            "6",
            "--config",
            "",
        ])
        .is_ok());
        // A dangling `-c` is still a parse error on both sides (Go: `flag
        // needs an argument: 'c' in -c`).
        let err = parse_frpc_tcp(&["tcp", "--local-port", "5", "--remote-port", "6", "-c"])
            .expect_err("dangling -c must be refused")
            .unwrap_stderr();
        assert!(
            err.contains("`-c` requires an argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn persistent_root_flags_tolerate_pflag_repetition() {
        // A repeated pflag flag is last-wins for scalars and appending for
        // slices, never an error — measured on Go v0.71.0, the tcp proxy still
        // starts with each of these.
        for extra in [
            vec!["-c", "a.toml", "-c", "b.toml"],
            vec!["--config-dir", "a", "--config-dir", "b"],
            vec!["--strict-config", "--strict-config=false"],
            vec!["--allow-unsafe", "a", "--allow-unsafe", "b"],
            vec!["--version", "--version"],
        ] {
            let argv = single_proxy_argv("tcp", SINGLE_PROXY_BASE[0].1, &extra);
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            assert!(
                frpc_parser().to_options().run_inner(&refs[..]).is_ok(),
                "repeated {extra:?} refused"
            );
        }
    }

    #[test]
    fn allow_unsafe_appends_and_comma_splits_on_every_reading_surface() {
        // pflag's `strings` value **appends** on repetition — it is not
        // last-wins — and Go comma-splits every occurrence. Measured on v0.71.0:
        // `frps verify`/`frpc verify` exit 0 for both value orders (and for
        // `Ignored,TokenSourceExec`), because any occurrence that enables
        // `TokenSourceExec` is enough. A last-wins reading would let a later
        // unrelated value cancel an earlier enabling one and so refuse a config
        // Go accepts, which is exactly the regression this pins.
        let verify = parse_frpc_verify(&[
            "verify",
            "-c",
            "p7520.toml",
            "--allow-unsafe",
            "WrongFeature",
            "--allow-unsafe",
            "Ignored,TokenSourceExec",
        ])
        .unwrap();
        assert_eq!(
            verify.allow_unsafe,
            ["WrongFeature", "Ignored", "TokenSourceExec"].map(String::from),
            "a repeated `--allow-unsafe` must append in order and comma-split each occurrence"
        );

        // Three occurrences, with the enabling value **last**. Every earlier pin
        // fed at most two occurrences, so a parser that capped the accumulation
        // at two stayed green while the shared parser regressed — measured: with
        // `.many().map(|mut v: Vec<String>| { v.truncate(2); v })` the gate
        // refused this row (rc 1) where the head and Go v0.71.0 are rc 0. The
        // full ordered vector is asserted, so truncation anywhere shows up here.
        let three = parse_frpc_verify(&[
            "verify",
            "-c",
            "p7520.toml",
            "--allow-unsafe",
            "WrongFeature",
            "--allow-unsafe",
            "Ignored",
            "--allow-unsafe",
            "TokenSourceExec",
        ])
        .unwrap();
        assert_eq!(
            three.allow_unsafe,
            ["WrongFeature", "Ignored", "TokenSourceExec"].map(String::from),
            "three occurrences must accumulate in order — capping at two drops the enabling value"
        );

        // Four occurrences, enabling value last: the next step out. Measured on
        // Go v0.71.0, four *and* five occurrences are each rc 0 on `frps verify`
        // and `frpc verify` — pflag's `strings` value has no cap at all — so a
        // literal row here buys one step rather than the class.
        let four = parse_frpc_verify(&[
            "verify",
            "-c",
            "p7520.toml",
            "--allow-unsafe",
            "A",
            "--allow-unsafe",
            "B",
            "--allow-unsafe",
            "Cc",
            "--allow-unsafe",
            "TokenSourceExec",
        ])
        .unwrap();
        assert_eq!(
            four.allow_unsafe,
            ["A", "B", "Cc", "TokenSourceExec"].map(String::from),
            "four occurrences must accumulate in order — capping at three drops the enabling value"
        );

        // The class itself: the accumulation is unbounded, so assert a wide
        // occurrence list instead of chasing the next `truncate(n)` one step at a
        // time. Any cap of at most 31 dies here; the literal rows above and the
        // two spawn pins keep the process-level rows honest (a spawn pin cannot
        // generate argv).
        let wide_n: usize = 32;
        let mut wide_argv = vec![
            "verify".to_string(),
            "-c".to_string(),
            "p7520.toml".to_string(),
        ];
        let mut wide_expected: Vec<String> =
            (0..wide_n - 1).map(|i| format!("Filler{i}")).collect();
        for value in &wide_expected {
            wide_argv.push("--allow-unsafe".to_string());
            wide_argv.push(value.clone());
        }
        wide_expected.push("TokenSourceExec".to_string());
        wide_argv.push("--allow-unsafe".to_string());
        wide_argv.push("TokenSourceExec".to_string());
        let wide = parse_frpc_verify(&wide_argv.iter().map(String::as_str).collect::<Vec<&str>>())
            .unwrap();
        assert_eq!(
            wide.allow_unsafe, wide_expected,
            "the occurrence list is unbounded — any cap of at most {wide_n} occurrences drops the \
             trailing enabling value"
        );

        let frps_verify = parse_frps_verify(&[
            "verify",
            "-c",
            "p7520.toml",
            "--allow-unsafe",
            "TokenSourceExec",
            "--allow-unsafe",
            "WrongFeature",
        ])
        .unwrap();
        assert_eq!(
            frps_verify.allow_unsafe,
            ["TokenSourceExec", "WrongFeature"].map(String::from),
            "the frps verify surface reads the same value and must append too"
        );

        // Both run paths read the value as well (the construction gate consumes
        // it), and Go accepts the repetition there: measured, `frps -c <exec
        // cfg> --allow-unsafe WrongFeature --allow-unsafe TokenSourceExec`
        // starts and logs its listener.
        let run = parse_frpc_run(&[
            "-c",
            "p7520.toml",
            "--allow-unsafe",
            "WrongFeature",
            "--allow-unsafe",
            "TokenSourceExec",
        ])
        .unwrap();
        assert_eq!(
            run.allow_unsafe,
            ["WrongFeature", "TokenSourceExec"].map(String::from)
        );
        // Three occurrences in the wrong order on the frps run path too: every
        // value survives, so an accumulation cap cannot hide here either.
        let frps_run = parse_frps(&[
            "-c",
            "p7520.toml",
            "--allow-unsafe",
            "TokenSourceExec",
            "--allow-unsafe",
            "Ignored",
            "--allow-unsafe",
            "WrongFeature",
        ])
        .unwrap();
        assert_eq!(
            frps_run.allow_unsafe,
            ["TokenSourceExec", "Ignored", "WrongFeature"].map(String::from),
            "a wrong-order three-occurrence run path keeps every value as well"
        );

        // The same value twice must survive **as two**. Every pin above feeds
        // distinct values, so a de-dup or last-wins reading stayed green —
        // measured, an accumulation that keeps only the last occurrence left
        // the whole frp-core lib suite green before this row existed.
        let repeated = parse_frpc_verify(&[
            "verify",
            "-c",
            "p7520.toml",
            "--allow-unsafe",
            "TokenSourceExec",
            "--allow-unsafe",
            "TokenSourceExec",
        ])
        .unwrap();
        assert_eq!(
            repeated.allow_unsafe,
            ["TokenSourceExec", "TokenSourceExec"].map(String::from),
            "an identical value repeated must be kept twice, not de-duplicated"
        );
        assert_eq!(
            read_ignored_allow_unsafe(&["--allow-unsafe", "Same", "--allow-unsafe", "Same"])
                .unwrap(),
            ["Same", "Same"].map(String::from),
            "the ignored twin de-duplicates nothing either"
        );

        // The class past any plausible cap, at both accumulation sites: 40
        // occurrences, and 40 CSV elements inside one occurrence. Measured
        // before these rows, a cap of 32 at either site (`v.truncate(32)` on the
        // accumulated vector, `split(',').take(32)` in the reader) left the whole
        // frp-core lib suite green — the widest row held exactly 32 values.
        let wide_n: usize = 40;
        let mut many_argv = vec![
            "verify".to_string(),
            "-c".to_string(),
            "p7520.toml".to_string(),
        ];
        let mut many_expected: Vec<String> = Vec::new();
        for i in 0..wide_n - 1 {
            let value = format!("Filler{i}");
            many_argv.push("--allow-unsafe".to_string());
            many_argv.push(value.clone());
            many_expected.push(value);
        }
        many_expected.push("TokenSourceExec".to_string());
        many_argv.push("--allow-unsafe".to_string());
        many_argv.push("TokenSourceExec".to_string());
        let many = parse_frpc_verify(&many_argv.iter().map(String::as_str).collect::<Vec<&str>>())
            .unwrap();
        assert_eq!(
            many.allow_unsafe, many_expected,
            "the occurrence list is unbounded — a cap of at most {wide_n} occurrences drops the \
             trailing enabling value"
        );

        let elements: Vec<String> = (0..wide_n - 1).map(|i| format!("Filler{i}")).collect();
        let csv_value = format!("{},TokenSourceExec", elements.join(","));
        let mut csv_expected = elements;
        csv_expected.push("TokenSourceExec".to_string());
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", &csv_value]).unwrap(),
            csv_expected,
            "the CSV element list is unbounded — a cap of at most {wide_n} elements drops the \
             trailing enabling value"
        );
        assert_eq!(
            read_ignored_allow_unsafe(&["--allow-unsafe", &csv_value]).unwrap(),
            csv_expected,
            "the ignored twin reads the same unbounded element list"
        );
    }

    #[test]
    fn allow_unsafe_reads_pflags_csv_record_on_both_parsers() {
        // pflag registers the flag as `StringSliceVarP` (frpc
        // `cmd/frpc/sub/root.go:55`, frps `cmd/frps/root.go:47`) and reads a
        // `strings` value through Go's `encoding/csv` (`LazyQuotes=false`,
        // `TrimLeadingSpace=false`), reading one record. Measured on Go v0.71.0
        // with `frpc verify -c <exec tokenSource cfg> --allow-unsafe <value>`:
        //   `"TokenSourceExec"`       rc 0 (matched quotes stripped)
        //   `A, TokenSourceExec`      rc 1 (leading space kept, so no match)
        //   `TokenSourceExec`         rc 0
        //   `Ignored,TokenSourceExec` rc 0
        //   (no flag)                 rc 1
        // The head read the value with `split(',').map(trim)`, so it accepted a
        // spaced element Go refuses and refused the quoted spelling Go accepts.
        let rows: [(&str, &[&str]); 4] = [
            ("\"TokenSourceExec\"", &["TokenSourceExec"]),
            ("A, TokenSourceExec", &["A", " TokenSourceExec"]),
            ("TokenSourceExec", &["TokenSourceExec"]),
            ("Ignored,TokenSourceExec", &["Ignored", "TokenSourceExec"]),
        ];
        for (value, expected) in rows {
            let expected: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
            assert_eq!(
                read_allow_unsafe(&["--allow-unsafe", value]).unwrap(),
                expected,
                "allow_unsafe_parser must read `{value}` the way pflag's CSV reader does"
            );
            assert_eq!(
                read_ignored_allow_unsafe(&["--allow-unsafe", value]).unwrap(),
                expected,
                "the ignored twin must read `{value}` identically (Go parses the persistent flag \
                 for every subcommand)"
            );
        }
        // The fifth row: with no flag both parsers yield no features.
        assert!(read_allow_unsafe(&[]).unwrap().is_empty());
        assert!(read_ignored_allow_unsafe(&[]).unwrap().is_empty());
    }

    #[test]
    fn allow_unsafe_csv_corners_are_go_shaped_and_never_trimmed() {
        // Quote corners, measured on Go v0.71.0 (all rc 0):
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", "\"a\"\"b\",TokenSourceExec"]).unwrap(),
            ["a\"b", "TokenSourceExec"],
            "a doubled quote inside a quoted element is one literal quote"
        );
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", "\"a,b\",TokenSourceExec"]).unwrap(),
            ["a,b", "TokenSourceExec"],
            "a comma inside quotes is data, not an element boundary"
        );
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", "\"\",TokenSourceExec"]).unwrap(),
            ["", "TokenSourceExec"],
            "an empty quoted element is an empty value, not an absent one"
        );
        // Empty elements are kept and whitespace is never trimmed. Measured:
        // `a,,b` parses as `a`, ``, `b` (Go rc 0 for `a,,TokenSourceExec`),
        // while ` TokenSourceExec`, `TokenSourceExec `, `A,\tTokenSourceExec`
        // and `'TokenSourceExec'` are all rc 1 — the head's `trim()` made the
        // first three rc 0.
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", "a,,b"]).unwrap(),
            ["a", "", "b"]
        );
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", " TokenSourceExec "]).unwrap(),
            [" TokenSourceExec "]
        );
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", "A,\tTokenSourceExec"]).unwrap(),
            ["A", "\tTokenSourceExec"]
        );
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", "'TokenSourceExec'"]).unwrap(),
            ["'TokenSourceExec'"],
            "single quotes are data — pflag only strips matched double quotes"
        );
        // A trailing CR is the line terminator, not data (Go rc 0 for
        // `TokenSourceExec\r`); a CR anywhere else is data (Go rc 1).
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", "TokenSourceExec\r"]).unwrap(),
            ["TokenSourceExec"]
        );
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", "\rTokenSourceExec"]).unwrap(),
            ["\rTokenSourceExec"]
        );
        // Only the first record is read: measured, `"TokenSourceExec"\njunk` is
        // rc 0 in Go — the second record is never parsed, malformed or not
        // (`A\n"unclosed` is the *gate* line, not a pflag parse error).
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", "\"TokenSourceExec\"\njunk"]).unwrap(),
            ["TokenSourceExec"]
        );
        // A record pflag refuses is refused here too, on both parsers, because
        // Go parses the persistent flag for every subcommand: measured, `frpc
        // tcp|status|reload -c <cfg> --allow-unsafe '"abc'` is rc 1 with
        // `Error: invalid argument "\"abc" for "--allow-unsafe" flag: parse
        // error on line 1, column 5: extraneous or missing " in quoted-field`.
        for bad in [
            "\"abc",
            "a\"b",
            "\"TokenSourceExec\"x",
            "\"TokenSourceExec\" ",
        ] {
            assert!(
                read_allow_unsafe(&["--allow-unsafe", bad]).is_err(),
                "allow_unsafe_parser must refuse `{bad}`"
            );
            assert!(
                read_ignored_allow_unsafe(&["--allow-unsafe", bad]).is_err(),
                "the ignored twin must refuse `{bad}` too"
            );
        }
    }

    #[test]
    fn allow_unsafe_skips_blank_lines_like_go_and_blank_only_is_an_eof_flag_error() {
        // Go's `encoding/csv` `readRecord` skips blank lines while reading a
        // record (`$GOROOT/src/encoding/csv/reader.go`), so a value that starts
        // with one still parses — measured on Go v0.71.0, `frpc verify -c <exec
        // cfg> --allow-unsafe $'\nTokenSourceExec'` is rc 0 while the head was
        // rc 1 (its reader never skipped the blank).
        for value in [
            "\nTokenSourceExec",
            "\n\nTokenSourceExec",
            "\r\nTokenSourceExec",
        ] {
            let expected = vec!["TokenSourceExec".to_string()];
            assert_eq!(
                read_allow_unsafe(&["--allow-unsafe", value]).unwrap(),
                expected,
                "leading blank lines must be skipped for {value:?}"
            );
            assert_eq!(
                read_ignored_allow_unsafe(&["--allow-unsafe", value]).unwrap(),
                expected,
                "the ignored twin must skip leading blank lines for {value:?}"
            );
        }
        // A blank line *inside* a quoted field is data, not a separator
        // (measured: `"a\n\nb"` is rc 1 with the gate line, not a parse error).
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", "\"a\n\nb\""]).unwrap(),
            ["a\n\nb"]
        );
        // A value that is nothing but blank lines leaves Go's reader with no
        // record at all: `readRecord` returns `io.EOF`, which pflag reports as
        // `invalid argument "\n" for "--allow-unsafe" flag: EOF` (measured, rc 1
        // on stderr — not the `unsafe feature …` gate line).
        for value in ["\n", "\r\n", "\n\n", "\r"] {
            assert_eq!(
                split_allow_unsafe_csv(value),
                Err("EOF".to_string()),
                "the reader must return Go's io.EOF for the blank-only value {value:?}"
            );
            for (label, parsed) in [
                (
                    "allow_unsafe_parser",
                    read_allow_unsafe(&["--allow-unsafe", value]),
                ),
                (
                    "ignored twin",
                    read_ignored_allow_unsafe(&["--allow-unsafe", value]),
                ),
            ] {
                let failure = parsed.expect_err(&format!("{label} must refuse {value:?}"));
                let rendered = failure.unwrap_stderr();
                assert!(
                    rendered.contains(": EOF"),
                    "{label} must report Go's EOF for {value:?}, got: {rendered}"
                );
            }
        }
        // The flip side of skipping blanks: the first record's terminator ends
        // the read, so a later malformed record is never parsed (measured: Go is
        // rc 1 on the gate line for `A\n"unclosed`).
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", "A\n\"unclosed"]).unwrap(),
            ["A"]
        );
        assert_eq!(
            read_ignored_allow_unsafe(&["--allow-unsafe", "A\n\"unclosed"]).unwrap(),
            ["A"]
        );
    }

    #[test]
    fn allow_unsafe_error_positions_are_go_lines_and_byte_columns() {
        // Go's `encoding/csv` `ParseError` counts 1-based **byte** columns on
        // 1-based lines, and prefixes `record on line N; ` when the error sits
        // on a later line than the record started on
        // (`$GOROOT/src/encoding/csv/reader.go`). Every row was measured on Go
        // v0.71.0 with `frpc verify` and `frps verify` (byte-identical); only
        // the `parse error …` tail is pinned, not frp-rs's surrounding sentence.
        let rows: [(&str, &str); 11] = [
            // The ASCII rows of the PR table keep their columns.
            (
                "\"abc",
                "parse error on line 1, column 5: extraneous or missing \" in quoted-field",
            ),
            (
                "\"TokenSourceExec\"x",
                "parse error on line 1, column 17: extraneous or missing \" in quoted-field",
            ),
            (
                "a\"b",
                "parse error on line 1, column 2: bare \" in non-quoted-field",
            ),
            // Multi-byte input: the column is bytes, not runes.
            (
                "\"é",
                "parse error on line 1, column 4: extraneous or missing \" in quoted-field",
            ),
            (
                "é\"x",
                "parse error on line 1, column 3: bare \" in non-quoted-field",
            ),
            (
                "x,é\"y",
                "parse error on line 1, column 5: bare \" in non-quoted-field",
            ),
            (
                "\"abc\r",
                "parse error on line 1, column 5: extraneous or missing \" in quoted-field",
            ),
            (
                "\"\"\"",
                "parse error on line 1, column 4: extraneous or missing \" in quoted-field",
            ),
            // A quoted field may span lines: the reported line advances and the
            // `record on line N; ` prefix appears.
            (
                "\"a\nbc\"x",
                "record on line 1; parse error on line 2, column 3: extraneous or missing \" in \
                 quoted-field",
            ),
            (
                "\"a\nb",
                "record on line 1; parse error on line 2, column 2: extraneous or missing \" in \
                 quoted-field",
            ),
            // The record itself starts on line 2 after the skipped blank, so
            // there is no prefix (the record line is the error line).
            (
                "\n\"a",
                "parse error on line 2, column 3: extraneous or missing \" in quoted-field",
            ),
        ];
        for (value, expected) in rows {
            // The reader's own message is Go's `ParseError` text exactly.
            assert_eq!(
                split_allow_unsafe_csv(value),
                Err(expected.to_string()),
                "the reader must place {value:?} at `{expected}`"
            );
            // And both parser surfaces must refuse it, since Go parses the
            // persistent flag for every subcommand.
            for (label, parsed) in [
                (
                    "allow_unsafe_parser",
                    read_allow_unsafe(&["--allow-unsafe", value]),
                ),
                (
                    "ignored twin",
                    read_ignored_allow_unsafe(&["--allow-unsafe", value]),
                ),
            ] {
                let failure = parsed.expect_err(&format!("{label} must refuse {value:?}"));
                // bpaf re-wraps the sentence when it renders it, so compare it
                // with whitespace collapsed.
                let rendered = failure.unwrap_stderr();
                let collapsed = rendered.split_whitespace().collect::<Vec<_>>().join(" ");
                assert!(
                    collapsed.contains(expected),
                    "{label} must relay `{expected}` for {value:?}, got: {rendered}"
                );
            }
        }
    }

    #[test]
    fn admin_subcommands_accept_the_root_flags_they_did_not_declare() {
        // `verify`/`reload`/`status`/`stop` already declare `-c` and
        // `--strict-config`; these are the other three Go puts on rootCmd.
        for cmd in ["reload", "status", "stop"] {
            let argv = [
                cmd,
                "-c",
                "p7498.toml",
                "--config-dir",
                "cDir",
                "--allow-unsafe",
                "TokenSourceExec",
                "--version",
            ];
            assert!(
                frpc_parser().to_options().run_inner(&argv[..]).is_ok(),
                "{cmd} refused the persistent root flags"
            );
        }
        assert!(parse_frpc_verify(&[
            "verify",
            "-c",
            "p7498.toml",
            "--config-dir",
            "cDir",
            "--allow-unsafe",
            "TokenSourceExec",
            "--version",
        ])
        .is_ok());
    }

    #[test]
    fn strict_config_value_grammar_is_still_go() {
        // The ignored flag keeps Go's pflag bool grammar, so a value Go
        // rejects is still rejected: measured, `--strict-config=foo` is
        // `Error: invalid argument "foo" for "--strict-config" flag:
        // strconv.ParseBool: …` (rc 1); frp-rs's message differs (recorded),
        // but it is not silently accepted.
        assert!(parse_frpc_tcp(&[
            "tcp",
            "--local-port",
            "5",
            "--remote-port",
            "6",
            "--strict-config=foo",
        ])
        .is_err());
        assert!(parse_frpc_tcp(&[
            "tcp",
            "--local-port",
            "5",
            "--remote-port",
            "6",
            "--strict-config=0",
        ])
        .is_ok());
    }

    #[test]
    fn single_proxy_help_lists_the_global_flags() {
        let failure = frpc_parser()
            .to_options()
            .run_inner(&["tcp", "--help"][..])
            .expect_err("tcp --help is reported as a ParseFailure");
        match failure {
            bpaf::ParseFailure::Stdout(doc, _) => {
                let text = doc.to_string();
                for flag in [
                    "-c",
                    "--config-dir",
                    "--strict-config",
                    "--allow-unsafe",
                    "--version",
                ] {
                    assert!(text.contains(flag), "tcp help lacks {flag}:\n{text}");
                }
            }
            other => panic!("expected help on stdout, got {other:?}"),
        }
    }

    // ── pflag's `-c <dash-value>` spelling, rewritten before bpaf ─────────

    fn rewrite(args: &[&str]) -> Vec<String> {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        rewrite_config_dash_values(&argv)
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn rewrite_attaches_a_dash_prefixed_config_value() {
        // Go: `frpc status -c --strict-config=false` is
        // `open --strict-config=false: no such file or directory` — pflag
        // consumes the token as `-c`'s value, flag-shaped or not.
        assert_eq!(
            rewrite(&["status", "-c", "--strict-config=false"]),
            vec!["status", "-c=--strict-config=false"]
        );
        // A pin, not a fix: bpaf already took `-foo` as a value (unknown
        // multi-character dash tokens are demoted to `Arg::Word`; measured at
        // the base head, `frpc status -c -foo.toml` read `-foo.toml`). The
        // rewrite must keep doing so via the attached spelling. The shapes it
        // actually repairs are the flag-shaped ones — `--long`, `-x`, `-c`,
        // `-a=b` (see `rewrite_config_dash_values`).
        assert_eq!(
            rewrite(&["status", "--config", "-foo"]),
            vec!["status", "--config=-foo"]
        );
        assert_eq!(
            rewrite(&["tcp", "--config-dir", "--strict-config=false"]),
            vec!["tcp", "--config-dir=--strict-config=false"]
        );
        // `--` is consumed as the value, exactly as Go does; the token after
        // it is therefore a plain word again (Go then parses `-foo` as a flag
        // and fails with `unknown shorthand flag: 'f' in -foo`, rc 1; frp-rs
        // reports the leftover token, also rc 1 — a recorded message-shape
        // divergence, not a behaviour one).
        assert_eq!(
            rewrite(&["tcp", "-c", "--", "-foo"]),
            vec!["tcp", "-c=--", "-foo"]
        );
    }

    #[test]
    fn rewrite_leaves_every_other_shape_alone() {
        // Ordinary values, attached spellings, dangling flags, non-config
        // flags and anything right of a real `--` are untouched.
        for argv in [
            vec!["status", "-c", "p7498.toml"],
            vec!["status", "-cp7498.toml"],
            vec!["status", "-c=p7498.toml"],
            vec!["status", "-c"],
            vec!["status", "--strict-config", "-c"],
            vec!["status", "--", "-c", "--foo"],
            vec!["status", "-c", "p7498.toml", "--", "-c", "p7499.toml"],
        ] {
            let expected: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
            assert_eq!(rewrite(&argv), expected, "rewrote {argv:?}");
        }
    }

    // ── The frps half of the same rewrite (the `-c <dash-value>` item in
    // `TODO.md`) ─────────────────────────────────────────────────────

    /// Run argv through the **shared preparation function** the binaries call
    /// ([`prepared_cli_argv`], used by both `parse_frps_args` and
    /// `parse_frpc_args`) and then through the frps parser, the way
    /// `parse_frps_args` does. Going through the shared function — rather than
    /// calling the rewrite directly — is what makes this a pin on the pair the
    /// entry point evaluates; the wiring itself (that `parse_frps_args` passes
    /// the prepared argv to `run_cli`) is what the argv-level tests in
    /// `frps/tests/cli_exit_codes.rs` fail on when it is reverted.
    ///
    /// Measured on Go frp v0.71.0: `frps -c --strict-config=false` is rc 1
    /// `open --strict-config=false: no such file or directory` — the token is
    /// `-c`'s value. Before this call site prepared the argv, frp-rs's parser
    /// exited with ``-c` requires an argument `FILE``.
    #[test]
    fn frps_takes_a_dash_shaped_config_value() {
        let argv: Vec<OsString> = ["-c", "--strict-config=false"]
            .iter()
            .map(OsString::from)
            .collect();
        let parsed = frps_args()
            .to_options()
            .run_inner(&prepared_cli_argv(&argv, RootCommand::Frps)[..])
            .expect("the prepared argv parses");
        assert_eq!(
            parsed.config.as_deref(),
            Some("--strict-config=false"),
            "the dash-shaped token must be `-c`'s value, not the flag"
        );

        // The long spelling, a value-taking frps flag, and a value that is
        // itself the config short flag.
        for (argv, expected) in [
            (&["--config", "-x"][..], "-x"),
            (&["-c", "--bind-port"][..], "--bind-port"),
            (&["-c", "-c"][..], "-c"),
        ] {
            let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
            let parsed = frps_args()
                .to_options()
                .run_inner(&prepared_cli_argv(&argv, RootCommand::Frps)[..])
                .unwrap_or_else(|err| {
                    panic!("frps {argv:?} must parse after the rewrite: {err:?}")
                });
            assert_eq!(
                parsed.config.as_deref(),
                Some(expected),
                "frps {argv:?} must take the dash-shaped token as the config value"
            );
        }

        // `--` consumed as the value takes it out of flag position, exactly as
        // it does on `frpc` (measured on Go v0.71.0 and on frp-rs:
        // `open --: no such file or directory`, rc 1, both). A word *after*
        // that value is a positional, and frp-rs refuses leftover positionals
        // with or without a `--` on both binaries — a pre-existing divergence
        // filed with the subcommand-after-root-flags item in `TODO.md`.
        let argv: Vec<OsString> = ["-c", "--"].iter().map(OsString::from).collect();
        let parsed = frps_args()
            .to_options()
            .run_inner(&prepared_cli_argv(&argv, RootCommand::Frps)[..])
            .expect("`-c --` parses with `--` as the value");
        assert_eq!(parsed.config.as_deref(), Some("--"));

        // Without the rewrite the same argv is still refused — this is what
        // makes the assertion above a pin on the preparation, not on bpaf.
        let raw: Vec<OsString> = ["-c", "--strict-config=false"]
            .iter()
            .map(OsString::from)
            .collect();
        assert!(
            frps_args().to_options().run_inner(&raw[..]).is_err(),
            "bpaf must still refuse the unprepared spelling — otherwise this test proves nothing"
        );
    }

    /// The rewrite's scope on `frps`: the same four config-selecting flags as
    /// `frpc`, so `--config-dir`/`--config_dir` (frp-rs extensions — Go frps has
    /// neither) get the same treatment, and a dash-shaped token anywhere else is
    /// left for bpaf.
    #[test]
    fn frps_rewrite_scope_matches_frpc() {
        assert_eq!(
            rewrite(&["--config-dir", "-x"]),
            vec!["--config-dir=-x"],
            "--config-dir is one of the four flags"
        );
        assert_eq!(
            rewrite(&["--config_dir", "-x"]),
            vec!["--config_dir=-x"],
            "--config_dir is the frp-rs alias and is one of the four flags"
        );
        // Not a config flag: a dash value here is bpaf's business, and on frps
        // `--bind-port` takes an integer, so this stays refused on both sides.
        assert_eq!(rewrite(&["--bind-port", "-x"]), vec!["--bind-port", "-x"]);
        assert_eq!(rewrite(&["-t", "-x"]), vec!["-t", "-x"]);
        // A real `--` on frps, with a config flag after it: untouched.
        assert_eq!(
            rewrite(&["-c", "p.toml", "--", "-c", "-x"]),
            vec!["-c", "p.toml", "--", "-c", "-x"]
        );
    }
    /// Batch H1, **Item A**: Go frp v0.71.0's proxy flag *names* must be accepted,
    /// and the frp-rs spellings they replace must keep parsing to the same field.
    ///
    /// Every probe drives the real parser, so a rename that only moved the
    /// rendered document (the `FRPC_*_DOC` whole-text pins) reds here too. Each
    /// `--custom-domain`/`--sd`/`--tls-server-name`/`--mux` value is deliberately
    /// distinct from the legacy one so a probe cannot pass by aliasing the wrong
    /// field.
    #[test]
    fn proxy_commands_accept_go_flag_names() {
        // http: `-d, --custom-domain strings` and `--sd string`.
        let FrpcCmd::Http(http) = parse_frpc_proxy(&[
            "http",
            "-l",
            "80",
            "--custom-domain",
            "go.example",
            "--sd",
            "go-sub",
        ])
        .expect("--custom-domain / --sd must parse on frpc http") else {
            panic!("expected the http command");
        };
        assert_eq!(http.custom_domains.as_str(), "go.example");
        assert_eq!(http.subdomain.as_deref(), Some("go-sub"));
        // The three legacy spellings are hidden aliases of the same fields.
        for argv in [
            &[
                "http",
                "-l",
                "80",
                "--custom-domains",
                "old.example",
                "--subdomain",
                "old-sub",
            ][..],
            &[
                "http",
                "-l",
                "80",
                "--custom_domain",
                "old.example",
                "--subdomain",
                "old-sub",
            ][..],
        ] {
            let FrpcCmd::Http(legacy) = parse_frpc_proxy(argv)
                .unwrap_or_else(|e| panic!("{argv:?} must keep parsing: {e:?}"))
            else {
                panic!("expected the http command");
            };
            assert_eq!(
                (legacy.custom_domains.as_str(), legacy.subdomain.as_deref()),
                ("old.example", Some("old-sub")),
                "{argv:?} must reach custom_domains/subdomain"
            );
        }

        // https: same two names, and `-d` is Go's shorthand.
        let FrpcCmd::Https(https) =
            parse_frpc_proxy(&["https", "-l", "443", "-d", "go.example", "--sd", "go-sub"])
                .expect("-d / --custom-domain / --sd must parse on frpc https")
        else {
            panic!("expected the https command");
        };
        assert_eq!(https.custom_domains.as_str(), "go.example");
        assert_eq!(https.subdomain.as_deref(), Some("go-sub"));

        // stcp/xtcp: `--tls-server-name string`, legacy `--server-name`/`--server_name`.
        for argv in [
            &[
                "stcp",
                "--sk",
                "s",
                "-l",
                "80",
                "--tls-server-name",
                "go.example",
            ][..],
            &[
                "xtcp",
                "--sk",
                "s",
                "-l",
                "80",
                "--tls-server-name",
                "go.example",
            ][..],
        ] {
            let (name, server_name) = match parse_frpc_proxy(argv)
                .unwrap_or_else(|e| panic!("{argv:?} must parse: {e:?}"))
            {
                FrpcCmd::Stcp(a) => ("stcp", a.server_name),
                FrpcCmd::Xtcp(a) => ("xtcp", a.server_name),
                other => panic!("expected stcp/xtcp, got {other:?}"),
            };
            assert_eq!(
                server_name.as_deref(),
                Some("go.example"),
                "{name} --tls-server-name must reach server_name"
            );
        }
        for argv in [
            &[
                "stcp",
                "--sk",
                "s",
                "-l",
                "80",
                "--server-name",
                "old.example",
            ][..],
            &[
                "xtcp",
                "--sk",
                "s",
                "-l",
                "80",
                "--server_name",
                "old.example",
            ][..],
        ] {
            let server_name = match parse_frpc_proxy(argv)
                .unwrap_or_else(|e| panic!("{argv:?} must keep parsing: {e:?}"))
            {
                FrpcCmd::Stcp(a) => a.server_name,
                FrpcCmd::Xtcp(a) => a.server_name,
                other => panic!("expected stcp/xtcp, got {other:?}"),
            };
            assert_eq!(
                server_name.as_deref(),
                Some("old.example"),
                "{argv:?} must keep reaching server_name"
            );
        }

        // tcpmux: Go's `--mux string` is the multiplexer *name*. frp-rs's own
        // `--mux-port` (a port the tcpmux path never used) survives as an
        // extension, and is optional because Go's command line has no port flag.
        let FrpcCmd::Tcpmux(tcpmux) =
            parse_frpc_proxy(&["tcpmux", "-l", "80", "--mux", "go-mux", "--mux-port", "7"])
                .expect("--mux / --mux-port must parse on frpc tcpmux")
        else {
            panic!("expected the tcpmux command");
        };
        assert_eq!(tcpmux.mux.as_deref(), Some("go-mux"));
        assert_eq!(tcpmux.mux_port, 7);
        assert_eq!(tcpmux.to_proxy_config().multiplexer, "go-mux");
        let FrpcCmd::Tcpmux(no_port) =
            parse_frpc_proxy(&["tcpmux", "-l", "80", "--mux", "httpconnect"])
                .expect("frpc tcpmux must parse without --mux-port, which Go has no flag for")
        else {
            panic!("expected the tcpmux command");
        };
        assert_eq!(no_port.mux_port, 0);
        assert_eq!(no_port.to_proxy_config().multiplexer, "httpconnect");
        let FrpcCmd::Tcpmux(bare) =
            parse_frpc_proxy(&["tcpmux", "-l", "80"]).expect("frpc tcpmux must still parse bare")
        else {
            panic!("expected the tcpmux command");
        };
        assert_eq!(
            bare.to_proxy_config().multiplexer,
            "httpconnect",
            "a bare frpc tcpmux must keep the pre-Item-A multiplexer default"
        );

        // stcp/xtcp: Go's `-n/--proxy-name`. Round 2 added the field, so this pins
        // that it reaches both the args and the proxy's wire name; the legacy
        // `--server-name` still lands on `server_name` (the two are separate
        // fields, and `proxy_name` wins when both are given).
        for argv in [
            &["stcp", "--sk", "s", "-l", "80", "--proxy-name", "go-name"][..],
            &["xtcp", "--sk", "s", "-l", "80", "--proxy-name", "go-name"][..],
        ] {
            let (name, proxy_name) = match parse_frpc_proxy(argv)
                .unwrap_or_else(|e| panic!("{argv:?} must parse: {e:?}"))
            {
                FrpcCmd::Stcp(a) => (a.to_proxy_config().name, a.proxy_name),
                FrpcCmd::Xtcp(a) => (a.to_proxy_config().name, a.proxy_name),
                other => panic!("expected stcp/xtcp, got {other:?}"),
            };
            assert_eq!(proxy_name.as_deref(), Some("go-name"));
            assert_eq!(name, "go-name", "{argv:?} must reach the proxy name");
        }

        // tcpmux: Go's `-d/--custom-domain strings` and `--sd string`. The comma
        // grammar is frp-rs's (Go's StringSlice takes repeats); the split must
        // reach `custom_domains` as a list.
        let FrpcCmd::Tcpmux(tcpmux_domains) = parse_frpc_proxy(&[
            "tcpmux",
            "-l",
            "80",
            "--custom-domain",
            "a.example,b.example",
            "--sd",
            "go-sub",
        ])
        .expect("--custom-domain / --sd must parse on frpc tcpmux") else {
            panic!("expected the tcpmux command");
        };
        assert_eq!(
            tcpmux_domains.custom_domains.as_deref(),
            Some("a.example,b.example")
        );
        assert_eq!(tcpmux_domains.subdomain.as_deref(), Some("go-sub"));
        let config = tcpmux_domains.to_proxy_config();
        assert_eq!(
            config.custom_domains,
            vec!["a.example".to_string(), "b.example".to_string()]
        );
        assert_eq!(config.subdomain, "go-sub");

        // sudp: Go's `--sk string`, optional like Go's (default ""). The long
        // `--remote-port` is frp-rs's own and still required; `-r` is refused.
        let FrpcCmd::Sudp(sudp) =
            parse_frpc_proxy(&["sudp", "-l", "80", "--remote-port", "1", "--sk", "go-sk"])
                .expect("--sk must parse on frpc sudp")
        else {
            panic!("expected the sudp command");
        };
        assert_eq!(sudp.sk.as_deref(), Some("go-sk"));
        assert_eq!(sudp.to_proxy_config().sk, "go-sk");
        let FrpcCmd::Sudp(no_sk) = parse_frpc_proxy(&["sudp", "-l", "80", "--remote-port", "1"])
            .expect("--sk is optional on frpc sudp, like Go")
        else {
            panic!("expected the sudp command");
        };
        assert_eq!(no_sk.sk, None);
        assert_eq!(no_sk.to_proxy_config().sk, "");
    }

    /// Batch H1, **Item B**: Go's proxy-command shorthands. Each `-x` must land on
    /// the field its Go long flag names, on every surface Go registers it on:
    /// `-i` local-ip, `-l` local-port, `-r` remote-port (tcp/udp only — Go's sudp
    /// registers no `remote_port`, so frp-rs's long-only copy takes no shorthand
    /// there), `-s` server-addr, `-P` server-port, `-n` proxy-name (all eight; Go
    /// registers it on every proxy command), and `-d` custom-domain.
    #[test]
    fn proxy_command_shorthands_parse_to_their_go_long_flag() {
        let FrpcCmd::Tcp(tcp) = parse_frpc_proxy(&[
            "tcp",
            "-i",
            "10.1.2.3",
            "-l",
            "8081",
            "-r",
            "18081",
            "-s",
            "srv.example",
            "-P",
            "7001",
            "-n",
            "probe",
        ])
        .expect("-i -l -r -s -P -n must parse on frpc tcp") else {
            panic!("expected the tcp command");
        };
        assert_eq!(
            (
                tcp.local_ip.as_str(),
                tcp.local_port,
                tcp.remote_port,
                tcp.server_addr.as_str(),
                tcp.server_port,
                tcp.proxy_name.as_deref(),
            ),
            ("10.1.2.3", 8081, 18081, "srv.example", 7001, Some("probe")),
            "-i/-l/-r/-s/-P/-n must be local-ip/local-port/remote-port/server-addr/server-port/proxy-name"
        );

        let FrpcCmd::Udp(udp) = parse_frpc_proxy(&[
            "udp",
            "-i",
            "10.1.2.3",
            "-l",
            "8082",
            "-r",
            "18082",
            "-s",
            "srv.example",
            "-P",
            "7002",
            "-n",
            "probe",
        ])
        .expect("-i -l -r -s -P -n must parse on frpc udp") else {
            panic!("expected the udp command");
        };
        assert_eq!(
            (
                udp.local_ip.as_str(),
                udp.local_port,
                udp.remote_port,
                udp.server_addr.as_str(),
                udp.server_port,
                udp.proxy_name.as_deref(),
            ),
            ("10.1.2.3", 8082, 18082, "srv.example", 7002, Some("probe"))
        );

        // http/https also need their required `--custom-domain`.
        let FrpcCmd::Http(http) = parse_frpc_proxy(&[
            "http",
            "-i",
            "10.1.2.3",
            "-l",
            "8083",
            "-s",
            "srv.example",
            "-P",
            "7003",
            "-n",
            "probe",
            "-d",
            "h.example",
        ])
        .expect("-i -l -s -P -n -d must parse on frpc http") else {
            panic!("expected the http command");
        };
        assert_eq!(
            (
                http.local_ip.as_str(),
                http.local_port,
                http.server_addr.as_str(),
                http.server_port,
                http.proxy_name.as_deref(),
                http.custom_domains.as_str(),
            ),
            (
                "10.1.2.3",
                8083,
                "srv.example",
                7003,
                Some("probe"),
                "h.example"
            )
        );

        let FrpcCmd::Https(https) = parse_frpc_proxy(&[
            "https",
            "-i",
            "10.1.2.3",
            "-l",
            "8084",
            "-s",
            "srv.example",
            "-P",
            "7004",
            "-n",
            "probe",
            "-d",
            "h.example",
        ])
        .expect("-i -l -s -P -n -d must parse on frpc https") else {
            panic!("expected the https command");
        };
        assert_eq!(
            (
                https.local_ip.as_str(),
                https.local_port,
                https.server_addr.as_str(),
                https.server_port,
                https.proxy_name.as_deref(),
            ),
            ("10.1.2.3", 8084, "srv.example", 7004, Some("probe"))
        );

        let FrpcCmd::Stcp(stcp) = parse_frpc_proxy(&[
            "stcp",
            "--sk",
            "s",
            "-i",
            "10.1.2.3",
            "-l",
            "8085",
            "-s",
            "srv.example",
            "-P",
            "7005",
            "-n",
            "probe",
        ])
        .expect("-i -l -s -P -n --sk must parse on frpc stcp") else {
            panic!("expected the stcp command");
        };
        assert_eq!(
            (
                stcp.local_ip.as_str(),
                stcp.local_port,
                stcp.server_addr.as_str(),
                stcp.server_port,
                stcp.proxy_name.as_deref(),
                stcp.sk.as_str(),
            ),
            ("10.1.2.3", 8085, "srv.example", 7005, Some("probe"), "s"),
            "-n must be proxy-name and --sk must be the secret key on frpc stcp"
        );

        let FrpcCmd::Xtcp(xtcp) = parse_frpc_proxy(&[
            "xtcp",
            "--sk",
            "s",
            "-i",
            "10.1.2.3",
            "-l",
            "8086",
            "-s",
            "srv.example",
            "-P",
            "7006",
            "-n",
            "probe",
        ])
        .expect("-i -l -s -P -n --sk must parse on frpc xtcp") else {
            panic!("expected the xtcp command");
        };
        assert_eq!(
            (
                xtcp.local_ip.as_str(),
                xtcp.local_port,
                xtcp.server_addr.as_str(),
                xtcp.server_port,
                xtcp.proxy_name.as_deref(),
                xtcp.sk.as_str(),
            ),
            ("10.1.2.3", 8086, "srv.example", 7006, Some("probe"), "s")
        );

        // Sudp takes no `-r` at all: Go's sudp has no `remote_port`, and the
        // v0.71.0 binary refuses both `-r` and `--remote-port` (measured). The
        // long form is frp-rs's own, so this pins it as long-only.
        let FrpcCmd::Sudp(sudp) = parse_frpc_proxy(&[
            "sudp",
            "-i",
            "10.1.2.3",
            "-l",
            "8087",
            "--remote-port",
            "18087",
            "-s",
            "srv.example",
            "-P",
            "7007",
            "-n",
            "probe",
            "--sk",
            "s",
        ])
        .expect("-i -l -s -P -n --sk --remote-port must parse on frpc sudp") else {
            panic!("expected the sudp command");
        };
        assert_eq!(
            (
                sudp.local_ip.as_str(),
                sudp.local_port,
                sudp.remote_port,
                sudp.server_addr.as_str(),
                sudp.server_port,
                sudp.proxy_name.as_deref(),
                sudp.sk.as_deref(),
            ),
            (
                "10.1.2.3",
                8087,
                18087,
                "srv.example",
                7007,
                Some("probe"),
                Some("s")
            )
        );
        assert!(
            parse_frpc_proxy(&["sudp", "-l", "1", "-r", "18087"]).is_err(),
            "frpc sudp -r must stay refused: Go registers no remote_port there"
        );

        let FrpcCmd::Tcpmux(tcpmux) = parse_frpc_proxy(&[
            "tcpmux",
            "-i",
            "10.1.2.3",
            "-l",
            "8088",
            "-s",
            "srv.example",
            "-P",
            "7008",
            "-n",
            "probe",
            "-d",
            "t.example",
            "--sd",
            "sub",
        ])
        .expect("-i -l -s -P -n -d --sd must parse on frpc tcpmux") else {
            panic!("expected the tcpmux command");
        };
        assert_eq!(
            (
                tcpmux.local_ip.as_str(),
                tcpmux.local_port,
                tcpmux.server_addr.as_str(),
                tcpmux.server_port,
                tcpmux.proxy_name.as_deref(),
                tcpmux.custom_domains.as_deref(),
                tcpmux.subdomain.as_deref(),
            ),
            (
                "10.1.2.3",
                8088,
                "srv.example",
                7008,
                Some("probe"),
                Some("t.example"),
                Some("sub")
            )
        );
    }
}

#[cfg(test)]
mod hoist_tests {
    use super::*;

    fn hoist(args: &[&str]) -> Vec<String> {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        hoist_leading_subcommand(&argv, RootCommand::Frpc)
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    fn prepared(args: &[&str]) -> Vec<String> {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        prepared_cli_argv(&argv, RootCommand::Frpc)
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    /// The same two helpers on the **`frps`** surface. They are separate
    /// functions rather than a parameter because every assertion below is about
    /// one root command's own flag/command set, and a shared helper would let a
    /// change to one root's set silently re-point the other's rows.
    fn hoist_frps(args: &[&str]) -> Vec<String> {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        hoist_leading_subcommand(&argv, RootCommand::Frps)
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    fn run_frps_cmd(args: &[&str]) -> Result<FrpsCmd, bpaf::ParseFailure> {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        let prepared = prepared_cli_argv(&argv, RootCommand::Frps);
        frps_parser().to_options().run_inner(&prepared[..])
    }

    /// The `frps` **run-path** parser ([`frps_args`]) only, for the assertions
    /// that the two extensions are still accepted there. The whole surface is
    /// [`run_frps_cmd`].
    fn parse_frps_run(args: &[&str]) -> Result<FrpsArgs, bpaf::ParseFailure> {
        frps_args().to_options().run_inner(args)
    }

    fn run_frpc(args: &[&str]) -> Result<FrpcCmd, bpaf::ParseFailure> {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        let prepared = prepared_cli_argv(&argv, RootCommand::Frpc);
        frpc_parser().to_options().run_inner(&prepared[..])
    }

    // ── the flag/value classifier ────────────────────────────────────────
    //
    // `consumes_value` decides whether the next argv token belongs to a flag
    // and therefore is never a subcommand candidate. Each row is cobra 1.8.0's
    // `stripFlags` reading (`command.go`): a `--long` without `=` consumes the
    // next token unless the flag carries `NoOptDefVal` (which is what
    // `--version` is), a two-character short without `=` likewise (`-v` is the
    // boolean), and anything with `=` or without a leading dash consumes
    // nothing.

    #[test]
    fn only_value_taking_tokens_swallow_the_next_arg() {
        for takes in [
            "-c",
            "--config",
            "--config-dir",
            "--config_dir",
            "--allow-unsafe",
            "-L",
            "-t",
            "-x",
            "--nodash",
            "--",
            // Deliberately a consumer although pflag makes it a bool: cobra
            // adds `--help` in `execute`, after `Find` ran `stripFlags`, so at
            // stripping time it is unknown. Measured, `frpc --help status`
            // prints help (rc 0) rather than resolving `status`.
            "--help",
            "-h",
        ] {
            assert!(
                consumes_value(OsStr::new(takes), RootCommand::Frpc),
                "{takes} must swallow the next token"
            );
        }
        for keeps in [
            "-v",
            "--version",
            "--version=false",
            // The two root pflag bools besides version (`cmd/frpc/sub/root.go:53`).
            // Both spellings, bare: cobra's `hasNoOptDefVal` is true for them, so
            // the next token is NOT consumed. Putting `--strict-config` back in
            // the list above is the regression `--strict-config true status`
            // measured (see `a_word_after_bare_strict_config_is_the_first_bare_word`).
            "--strict-config",
            "--strict_config",
            "--strict-config=false",
            "-c=p.toml",
            "-cp.toml",
            "--config=p.toml",
            "-c=",
            "-",
            "",
            "status",
            "p.toml",
        ] {
            assert!(
                !consumes_value(OsStr::new(keeps), RootCommand::Frpc),
                "{keeps} must not swallow the next token"
            );
        }
    }

    // ── the `--help=<bool>` pass (TODO.md:4981) ─────────────────────────
    //
    // Every row in these two tests carries the Go v0.71.0 measurement it pins,
    // taken with one fresh listening socket per run on the config's
    // `[webServer] port` and the connection count read from `accept`:
    // `--help=false status -c CFG` is rc 1 with **1** connection (`status` ran and
    // dialled), `--help=true status -c CFG` is rc 0 with 0 connections and
    // `status`'s help, and `-hc status` is rc 1 with the missing-argument line on
    // stderr and 0 B on stdout.

    /// Go's pflag bool makes `--help=false` a *value*, not a request: the command
    /// still resolves and runs. bpaf's built-in help parser pre-empted that, so
    /// the pass drops the token when a command word follows it and appends a bare
    /// `--help` when the value is true.
    #[test]
    fn help_bool_value_form_is_stripped_only_before_a_command() {
        assert_eq!(
            prepared(&["--help=false", "status", "-c", "pA.toml"]),
            ["status", "-c", "pA.toml"]
        );
    }

    /// The shapes, measured one by one. `prepared` runs the whole chain the
    /// binaries run — the config dash-value rewrite, the hoist, this pass and the
    /// shorthand detector — so a row failing here is a row the binary would get
    /// wrong.
    #[test]
    fn help_bool_value_form_rows_match_go() {
        // The command is hoisted past the flag, and the flag becomes a bare
        // `--help` **at the end** so the subcommand's own help is what prints
        // (`--help=true status` and `status --help` are byte-identical on Go).
        assert_eq!(
            prepared(&["--help=true", "status", "-c", "pA.toml"]),
            ["status", "-c", "pA.toml", "--help"]
        );
        assert_eq!(prepared(&["--help=true", "status"]), ["status", "--help"]);
        // `false` is dropped with no replacement, so the command runs.
        assert_eq!(
            prepared(&["--help=false", "status", "-c", "pA.toml"]),
            ["status", "-c", "pA.toml"]
        );
        assert_eq!(prepared(&["--help=false", "verify"]), ["verify"]);
        // The underscore-suffixed values Go's `strconv.ParseBool` accepts.
        assert_eq!(
            prepared(&["--help=0", "status", "-c", "pA.toml"]),
            ["status", "-c", "pA.toml"]
        );
        assert_eq!(prepared(&["--help=1", "status"]), ["status", "--help"]);
        // Every other spelling of the same key is left for bpaf, because it is
        // not `--help=<bool>`: `--help`, `-h`, `--helpfalse` (no `=`) and the
        // prefix `--helpful=x`.
        for untouched in [
            vec!["--help", "status"],
            vec!["-h", "status"],
            vec!["--helpfalse", "status"],
        ] {
            assert_eq!(
                prepared(&untouched),
                untouched,
                "{untouched:?} is not `--help=<bool>`"
            );
        }
        // `--helpful=x` is not `--help=<bool>` either, but it *is* a flag the
        // hoist sees as value-taking, so `status` is hoisted past it — the
        // pre-existing `unknown flag` treatment, unchanged by this pass.
        assert_eq!(
            prepared(&["--helpful=x", "status"]),
            ["status", "--helpful=x"]
        );
        // The space form is **not** `--help=<bool>`, but it is still hoisted:
        // `--help` is a consumer, so `false` is its value and `status` is the
        // first bare word. Pre-existing (the hoist predates this pass) and pinned
        // here so the two passes cannot start disagreeing about it.
        assert_eq!(
            prepared(&["--help", "false", "status"]),
            ["status", "--help", "false"]
        );
        // No command word → the pass leaves the token alone: this is the
        // pre-existing root divergence (`frpc --help=false -c cfg` prints help
        // here and starts the client on Go, rc 124, `TODO.md:4981`), and
        // `--help=true notacommand` must keep bpaf's refusal rather than be
        // cleaned up into root help.
        for untouched in [
            vec!["--help=false", "-c", "pA.toml"],
            vec!["--help=true"],
            vec!["--help=true", "notacommand"],
            vec!["--help=false", "notacommand"],
        ] {
            assert_eq!(
                prepared(&untouched),
                untouched,
                "{untouched:?} has no command word"
            );
        }
        // …and a word in `-c`'s value position is not a command word either, so
        // a `status` hiding there is never promoted to one — and the flag is not
        // stripped on its account.
        assert_eq!(
            prepared(&["--help=false", "-c", "status"]),
            ["--help=false", "-c", "status"]
        );
        // Nothing after a real `--` is a flag — `-c --help` is `-c`'s value, and
        // the rewrite has already attached it by the time this pass looks.
        assert_eq!(
            prepared(&["-c", "--help=false", "status"]),
            ["status", "-c=--help=false"]
        );
    }

    /// A `--help=<bool>` token that pflag hands to another flag as its **value**
    /// is not a help request, and must survive untouched. R2's F1: six measured
    /// rows where the head used to strip it and then fail or print help.
    #[test]
    fn a_help_token_in_a_value_position_is_not_a_request() {
        // `frpc -hc --help=false status` — the cluster's `c` takes the token, so
        // Go answers with **`status`'s** help and rc 0 (measured: 627 B,
        // `Overview of all proxies status`) and the base head agreed at 1604 B of
        // bpaf usage. Stripping the token left `-hc` dangling and refused an argv
        // both trees parse.
        assert_eq!(
            prepared(&["-hc", "--help=false", "status"]),
            ["status", "-hc", "--help=false"]
        );
        // The config flags: `--config` / `-c` take the token, so the config read
        // is what fails (Go: `open --help=false: no such file or directory`,
        // rc 1, 81 B on stdout) instead of a help print.
        // (`-c`'s dash-value rewrite runs first, so those two reach the hoist
        // as one attached token and the command is hoisted past them.)
        assert_eq!(
            prepared(&["--config", "--help=false", "status"]),
            ["status", "--config=--help=false"]
        );
        assert_eq!(
            prepared(&["-c", "--help=false", "status"]),
            ["status", "-c=--help=false"]
        );
        // …and `<long>=<value>` spellings keep their own `=`, so the pass never
        // sees them as `--help=`.
        assert_eq!(
            prepared(&["status", "--admin-addr=--help=false"]),
            ["status", "--admin-addr=--help=false"]
        );
    }

    /// pflag's consumption walk, and the argv that reached bpaf's help instead
    /// of its error. Each `Some` row is a Go rc 1 whose line must be
    /// `Error: flag needs an argument: '<c>' in -<c>`; each `None` row is argv
    /// that must be left for the parser.
    ///
    /// The rows go through the rewrite, the attachment and the expansion — the
    /// passes that run before the refusal — but not `prepared`, which would call
    /// the exiter. The walk is what decides: a `-h<short>` cluster *claims* the
    /// token after it (`frpc -hc -hc`, `frpc -hc -v`), so only a cluster with
    /// nothing left to take is reported.
    #[test]
    fn shorthand_cluster_needing_a_value_is_detected() {
        let prepared_before_reject = |args: &[&str]| {
            let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
            let rewritten = rewrite_config_dash_values(&argv);
            let attached = attach_flag_shaped_values(rewritten, RootCommand::Frpc);
            let hoisted = hoist_leading_subcommand(&attached, RootCommand::Frpc);
            expand_help_bool_value_form(hoisted, RootCommand::Frpc)
        };
        for (argv, expected) in [
            // Go rc 1, stderr, 0 B on stdout: the cluster is last and takes
            // nothing. `-hc status` also reports `c` — pflag hands `status` to
            // the cluster as its value and the *status* parser then sees `-hc`
            // with nothing after it (637 B, measured).
            (vec!["-hc"], Some('c')),
            (vec!["-hc", "status"], Some('c')),
            (vec!["status", "-hc"], Some('c')),
            (vec!["-c", "CFG", "-hc"], Some('c')),
            // Go rc 0 with root help (measured 1370 B): the cluster took the
            // next token, whatever it is.
            (vec!["-hc", "-hc"], None),
            (vec!["-hc", "-hL"], None),
            (vec!["-hc", "-h"], None),
            (vec!["-hc", "-v"], None),
            (vec!["-hc", "-c"], None),
            // …and the same once the hoist has moved the command word in front:
            // `frpc -hc status -v` / `-c` / `-c CFG` are all Go rc 0 (627 B of
            // `status` help).
            (vec!["-hc", "status", "-c"], None),
            (vec!["-hc", "status", "-c", "CFG"], None),
            (vec!["-hc", "status", "-v"], None),
            (vec!["-hc", "status", "-t"], None),
            // `-L` is frp-rs's run-path short, so the **root** context reports
            // it (Go has no `-L` at all: `unknown shorthand flag: 'L' in -L`,
            // rc 1 — the message differs, the rc and stream agree).
            (vec!["-hL"], Some('L')),
            // The subcommands of **both** binaries do not have `-L` in frp-rs, so
            // no fabricated `flag needs an argument: 'L'` line there.
            (vec!["status", "-hL"], None),
            (vec!["tcp", "-hL"], None),
            (vec!["verify", "-hL"], None),
            // A bare help flag followed by a bare dangling short is reported
            // (R2's F2): `frpc -h -c` is Go rc 1 with pflag's line on stderr.
            (vec!["-h", "-c"], Some('c')),
            (vec!["--help", "-t"], Some('t')),
            (vec!["status", "-h", "-c"], Some('c')),
            // …while the reverse order is the *short* taking `-h` as its value.
            (vec!["-t", "-h"], None),
            (vec!["-c", "-h"], None),
            // The cluster carries its value, or names something that cannot take
            // one.
            (vec!["-hcx"], None),
            (vec!["-hc=x"], None),
            (vec!["-hLinfo"], None),
            (vec!["-h"], None),
            (vec!["-c"], Some('c')),
            (vec!["--help=false"], None),
            (vec!["-h", "status"], None),
        ] {
            let items = prepared_before_reject(&argv);
            assert_eq!(
                walk_argv(
                    &items,
                    ShortFlagContext::of(&items, RootCommand::Frpc),
                    RootCommand::Frpc
                )
                .needs_argument,
                expected,
                "{argv:?} reaches the walk as {items:?} and must be {expected:?}"
            );
        }
    }

    /// M1: the two **roots** do not share a short set. `-L` is `frpc`'s run-path
    /// alias for `--log-level`; `frps`'s root has no such short in frp-rs *or* in
    /// Go (`log_level` is registered with an empty shorthand,
    /// `pkg/config/flags.go:244`). Sharing the sets made `frps -hL` print a
    /// fabricated `flag needs an argument: 'L' in -L` where the base and Go are
    /// rc 1 with bpaf's own refusal (measured: base == head, stderr 45 B).
    #[test]
    fn the_root_shorts_are_per_binary() {
        assert!(value_taking_root_shorts(RootCommand::Frpc).contains(&'L'));
        assert!(!value_taking_root_shorts(RootCommand::Frps).contains(&'L'));
        let argv: Vec<OsString> = ["-hL"].iter().map(OsString::from).collect();
        assert_eq!(
            walk_argv(
                &argv,
                ShortFlagContext::of(&argv, RootCommand::Frpc),
                RootCommand::Frpc
            )
            .needs_argument,
            Some('L'),
            "frpc's run path registers -L, so the cluster is reported"
        );
        assert_eq!(
            walk_argv(
                &argv,
                ShortFlagContext::of(&argv, RootCommand::Frps),
                RootCommand::Frps
            )
            .needs_argument,
            None,
            "frps has no -L, so nothing may be fabricated"
        );
    }

    /// A flag-shaped value is attached to the flag that owns it, because bpaf
    /// cannot see a value that starts with `-`. R2's F2b: `frps -c CFG -t -h`
    /// must take `-h` as `--token`'s value (Go loads the config and exits 1),
    /// where the base head printed root help with rc 0.
    #[test]
    fn a_flag_shaped_value_is_attached_to_its_flag() {
        let attach = |args: &[&str]| {
            let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
            let rewritten = rewrite_config_dash_values(&argv);
            attach_flag_shaped_values(rewritten, RootCommand::Frps)
        };
        assert_eq!(attach(&["-c", "CFG", "-t", "-h"]), ["-c", "CFG", "-t=-h"]);
        assert_eq!(attach(&["-t", "-h"]), ["-t=-h"]);
        assert_eq!(attach(&["-p", "-h"]), ["-p=-h"]);
        // The **long** flags too, including a value that carries its own `=`:
        // `frps verify --token --help=false -c CFG` must hand `--help=false` to
        // `--token` (Go parses it and exits 0 with `syntax is ok`, 116 B; a
        // short-only list left `--token` with no argument and exited 1).
        assert_eq!(
            attach(&["verify", "--token", "--help=false", "-c", "CFG"]),
            ["verify", "--token=--help=false", "-c", "CFG"]
        );
        assert_eq!(
            attach(&["verify", "--bind-addr", "--help=false"]),
            ["verify", "--bind-addr=--help=false"]
        );
        assert_eq!(
            attach(&["verify", "--log_file", "--help=false"]),
            ["verify", "--log_file=--help=false"]
        );
        assert_eq!(attach(&["--log-level", "-h"]), ["--log-level=-h"]);
        // **Not** attached: the frp-rs bools, whose value branch is
        // `.adjacent()` so a separate token is never their value, and the names
        // frp-rs does not register at all. Attaching these was the round-3
        // regression: `frps verify --dashboard_tls_mode -c CFG` became
        // `--dashboard_tls_mode=-c` and the bool parser refused the value (Go and
        // the base: rc 0, 114 B on stdout), and `frpc tcp --disable-log-color -h`
        // / `--ue -h` / `--tls_enable -h` became errors where both trees print
        // help with rc 0.
        for untouched in [
            vec!["verify", "--dashboard_tls_mode", "-c", "CFG"],
            vec![
                "verify",
                "--dashboard-tls-mode",
                "--help=false",
                "-c",
                "CFG",
            ],
            vec!["tcp", "--disable-log-color", "-h"],
            vec!["tcp", "--ue", "-h"],
            vec!["tcp", "--uc", "-h"],
            vec!["stcp", "--tls_enable", "-h"],
            vec!["tcp", "--version", "-h"],
            vec!["status", "--json", "-h"],
            vec!["--strict-config", "-h"],
            vec!["-h", "-c"],
            vec!["-hc", "-h"],
        ] {
            assert_eq!(
                attach(&untouched),
                untouched,
                "{untouched:?} must be left alone"
            );
        }
        // The long list is what decides that, so pin its shape in both
        // directions: the names the measured rows need are members, and every
        // frp-rs bool is not.
        for member in [
            "token",
            "bind-addr",
            "bind-port",
            "bind_port",
            "log_file",
            "log-level",
            "config",
            "config_dir",
            "allow-unsafe",
            "proxy-name",
        ] {
            assert!(
                VALUE_TAKING_LONG_FLAGS.contains(&member),
                "{member} must be listed"
            );
        }
        for absent in [
            "ue",
            "uc",
            "tls_enable",
            "disable-log-color",
            "dashboard-tls-mode",
            "dashboard_tls_mode",
            "version",
            "strict-config",
            "strict_config",
            "json",
            "enable-prometheus",
            "tls-only",
        ] {
            assert!(
                !VALUE_TAKING_LONG_FLAGS.contains(&absent),
                "{absent} must not be listed"
            );
        }
        // Nothing to attach when the value is bare, and nothing to attach a
        // *bool* short to: `frpc -v -h` is `-v` plus a help request on both
        // trees, not `--version="-h"`.
        assert_eq!(attach(&["-c", "CFG", "-t", "X"]), ["-c", "CFG", "-t", "X"]);
        assert_eq!(attach(&["-v", "-h"]), ["-v", "-h"]);
        assert_eq!(attach(&["--help", "-h"]), ["--help", "-h"]);
        assert_eq!(attach(&["--version", "-h"]), ["--version", "-h"]);
        assert_eq!(
            attach(&["--strict-config", "-h"]),
            ["--strict-config", "-h"]
        );
        // A cluster is a consumer too: `frpc -hc -h` gives `-h` to the `c`.
        // A cluster is a consumer too, and `-v` is a bool short with no `-v=`
        // spelling, so only the flag-shaped value of a **config** flag is
        // attached as well (`frpc -c --help=false status` is
        // `-c=--help=false`, the rewrite that already existed).
        assert_eq!(attach(&["-hc", "status", "-v"]), ["-hc", "status", "-v"]);
        // An already-attached token is left alone, and `--` still ends the pass.
        assert_eq!(attach(&["-c=-h"]), ["-c=-h"]);
        assert_eq!(attach(&["--", "-t", "-h"]), ["--", "-t", "-h"]);
    }

    /// The **value grammar** and the rejection are pflag's even though the
    /// *document* is now cobra's (rendered by `render_cobra_help`):
    /// `--help=<anything not a `strconv.ParseBool`
    /// spelling>` is refused with pflag's line and rc 1, which is a different
    /// answer from the base head's root help (measured: Go rc 1, 698 B on
    /// stderr for `--help=foo status`; base head rc 0, 1604 B of `status` usage
    /// on stdout; head rc 1 with the same 102 B pflag-shaped line as the other
    /// bool flags). The passing values are the twelve Go accepts, so this is a
    /// table over `parse_go_bool`.
    #[test]
    fn help_bool_value_form_uses_go_bool_spellings() {
        for (value, is_true) in [
            ("1", true),
            ("t", true),
            ("T", true),
            ("TRUE", true),
            ("true", true),
            ("True", true),
            ("0", false),
            ("f", false),
            ("F", false),
            ("FALSE", false),
            ("false", false),
            ("False", false),
        ] {
            let mut args = vec![format!("--help={value}"), "status".to_string()];
            if !is_true {
                args.push("-c".to_string());
                args.push("pA.toml".to_string());
            }
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let mut expected = vec!["status"];
            if !is_true {
                expected.extend(["-c", "pA.toml"]);
            } else {
                expected.push("--help");
            }
            assert_eq!(prepared(&argv), expected, "--help={value}");
        }
        // Out-of-grammar values exit the process, so they cannot be observed
        // from inside this test binary; the binary-level rc and the exact
        // stderr line for `--help=foo` are measured in the probe (Go 698 B,
        // head 102 B, both rc 1 with 0 B on stdout) and recorded in
        // `docs/developing.md`.
    }

    /// Direction B (R1): a bare `--strict-config`/`--strict_config` before the
    /// command word does **not** consume it, so the command is hoisted.
    /// Measured on Go v0.71.0: `frpc --strict-config status -c cfg` is rc 0 and
    /// dials the config's admin port; so are `--strict_config status -c cfg`,
    /// `-c cfg --strict-config status` and `--strict-config tcp …`.
    #[test]
    fn a_bare_strict_config_does_not_swallow_the_subcommand() {
        assert_eq!(
            hoist(&["--strict-config", "status", "-c", "pA.toml"]),
            ["status", "--strict-config", "-c", "pA.toml"]
        );
        assert_eq!(
            hoist(&["--strict_config", "status", "-c", "pA.toml"]),
            ["status", "--strict_config", "-c", "pA.toml"]
        );
        assert_eq!(
            hoist(&["-c", "pA.toml", "--strict-config", "status"]),
            ["status", "-c", "pA.toml", "--strict-config"]
        );
        assert_eq!(
            hoist(&["-c", "pA.toml", "--strict_config", "status"]),
            ["status", "-c", "pA.toml", "--strict_config"]
        );
        // The same on a single-proxy command and with a second `-c`.
        assert_eq!(
            hoist(&["--strict-config", "tcp", "--local-port", "5"]),
            ["tcp", "--strict-config", "--local-port", "5"]
        );
        assert_eq!(
            hoist(&["--strict-config", "status", "-c", "a.toml", "-c", "b.toml"]),
            ["status", "--strict-config", "-c", "a.toml", "-c", "b.toml"]
        );
        // And the hoisted argv parses as the command, not as run mode.
        match run_frpc(&["--strict-config", "status", "-c", "pA.toml"])
            .expect("the hoisted argv parses")
        {
            FrpcCmd::Status(args) => assert_eq!(args.config.as_deref(), Some("pA.toml")),
            other => panic!("expected the status command, got {other:?}"),
        }
    }

    /// Direction A (R2, the regression): a *word* after a bare
    /// `--strict-config` is the first bare word, and it is not a command, so
    /// **no** token is hoisted — in particular not the real command name that
    /// follows it. Measured on Go v0.71.0: `frpc --strict-config true status -c
    /// cfg` is rc 1 `unknown command "true" for "frpc"` and never dials.
    /// `--help`/`-h` stays a consumer, measured rather than assumed: cobra
    /// registers the help flag in `execute` (`cobra-1.8.0/command.go:885`),
    /// after `Find` (`:1090`) ran `stripFlags`, so it is unknown at stripping
    /// time. The argv below must therefore be left alone — hoisting `status`
    /// would make frp-rs print the *status* help where Go prints the root's.
    #[test]
    fn help_does_not_become_a_candidate() {
        for argv in [
            vec!["--help", "status"],
            vec!["-h", "status"],
            vec!["--help", "notacommand"],
            vec!["-h", "notacommand"],
            vec!["--help", "tcp", "--local-port", "5"],
            vec!["-c", "pA.toml", "--help", "status"],
        ] {
            assert_eq!(hoist(&argv), argv, "{argv:?} must not be rewritten");
        }
        // And the parse really is the root's: bpaf reports help on stdout with
        // the root usage line, not a `status` subcommand usage.
        let prepared = prepared_cli_argv(
            &[OsString::from("--help"), OsString::from("status")],
            RootCommand::Frpc,
        );
        assert_eq!(prepared.len(), 2, "no token may be hoisted");
        let failure = frpc_parser()
            .to_options()
            .run_inner(&prepared[..])
            .expect_err("--help is reported as a ParseFailure");
        match failure {
            bpaf::ParseFailure::Stdout(doc, _) => {
                let text = doc.to_string();
                // The root usage lists its command alternatives; a selected
                // subcommand's help is a bare `Usage: COMMAND ...` with no
                // alternation.
                assert!(
                    text.contains("(COMMAND ..."),
                    "the ROOT usage must be printed, not the status command's:\n{text}"
                );
            }
            other => panic!("expected help on stdout, got {other:?}"),
        }
    }

    #[test]
    fn a_word_after_bare_strict_config_is_the_first_bare_word() {
        for argv in [
            vec!["--strict-config", "true", "status", "-c", "pA.toml"],
            vec!["--strict-config", "false", "status", "-c", "pA.toml"],
            vec!["--strict_config", "true", "stop", "-c", "pA.toml"],
            vec!["--strict-config", "true", "tcp", "--local-port", "5"],
            vec!["--strict-config", "true", "reload", "-c", "pA.toml"],
            // `notacommand` is refused by Go as the first bare word; the real
            // command after it must not be hoisted either.
            vec!["--strict-config", "notacommand", "status"],
        ] {
            let out = hoist(&argv);
            assert_eq!(
                out, argv,
                "{argv:?} must not be rewritten: the word after the bare flag is the first bare word"
            );
        }
    }

    // ── the hoist itself ────────────────────────────────────────────────

    #[test]
    fn a_subcommand_after_leading_root_flags_is_hoisted() {
        assert_eq!(
            hoist(&["-c", "pA.toml", "status"]),
            ["status", "-c", "pA.toml"]
        );
        assert_eq!(
            hoist(&["--strict-config=false", "status", "-c", "pA.toml"]),
            ["status", "--strict-config=false", "-c", "pA.toml"]
        );
        assert_eq!(
            hoist(&["-c", "pA.toml", "--strict-config=false", "status"]),
            ["status", "-c", "pA.toml", "--strict-config=false"]
        );
        // The value is a flag-shaped token, so the rewrite has already attached
        // it and the bare word is the candidate.
        assert_eq!(
            hoist(&["-c=--strict-config=false", "status", "-c", "pA.toml"]),
            ["status", "-c=--strict-config=false", "-c", "pA.toml"]
        );
    }

    #[test]
    fn an_already_leading_subcommand_is_left_alone() {
        // frp-rs's own order must keep working; `i > 0` is what keeps this a
        // no-op rather than an identity rewrite.
        for argv in [
            vec!["status", "-c", "pA.toml"],
            vec!["tcp", "--local-port", "5"],
            vec!["verify", "-c", "p.toml"],
        ] {
            let out = hoist(&argv);
            assert_eq!(out, argv, "leading subcommand was reordered");
        }
    }

    #[test]
    fn a_value_that_names_a_subcommand_is_never_hoisted() {
        // The value-position traps, each measured on Go v0.71.0 (the full table
        // is in `docs/developing.md` § CLI inputs).
        for argv in [
            // a config file literally named after a command: `-c`'s value
            vec!["-c", "status"],
            vec!["-c", "tcp"],
            vec!["--config", "run"],
            // `=`-attached: the value lives inside the flag token
            vec!["--config=status"],
            vec!["-c=status"],
            vec!["-cstatus"],
            // a dash-shaped value
            vec!["-c", "-status"],
            vec!["-c", "--status"],
            // a real `--` ends the scan: `status` is a positional there
            vec!["--", "status"],
            vec!["-c", "cfg.toml", "--", "status"],
            // a subcommand already leads, so its option values are its own
            vec!["tcp", "--proxy-name", "status", "--local-port", "5"],
        ] {
            let out = hoist(&argv);
            assert_eq!(out, argv, "{argv:?} must not be rewritten");
        }
    }

    #[test]
    fn only_the_first_bare_word_can_be_a_candidate() {
        // Go refuses the first bare word (`unknown command "notacommand" for
        // "frpc"`, measured) even when a real command follows it, so a later
        // word is never hoisted.
        for argv in [
            vec!["-c", "pA.toml", "notacommand"],
            vec!["-c", "pA.toml", "notacommand", "status"],
            vec!["nathole"],
            vec!["completion"],
            vec!["help"],
            vec!["STATUS"],
        ] {
            let out = hoist(&argv);
            assert_eq!(out, argv, "{argv:?} must not be rewritten");
        }
    }

    // ── the composition with the rewrite ────────────────────────────────

    #[test]
    fn the_rewrite_runs_before_the_hoist() {
        // `-c -- status`: pflag gives `-c` the value `--`, so there is no
        // separator left and `status` is the first bare word. Measured on Go
        // v0.71.0: `frpc -c -- status` resolves the `status` subcommand and
        // fails on `open --: no such file or directory` — the config read
        // happens on the admin path, not in run mode.
        assert_eq!(prepared(&["-c", "--", "status"]), ["status", "-c=--"]);
        // With no rewrite in front, `-c` still takes `--` as its value: the
        // separator check is reached only at a token position that is not a
        // flag's value, which for this argv never happens.
        assert_eq!(hoist(&["-c", "--", "status"]), ["status", "-c", "--"]);
        // The separator is real at the front, though, and stops the scan.
        assert_eq!(prepared(&["--", "status"]), ["--", "status"]);
        // A flag-shaped value is attached, never a candidate.
        assert_eq!(
            prepared(&["-c", "--strict-config=false"]),
            ["-c=--strict-config=false"]
        );
        assert_eq!(
            prepared(&["-c", "--strict-config=false", "status"])
                .first()
                .map(String::as_str),
            Some("status")
        );
    }

    #[test]
    fn the_hoisted_argv_parses_as_the_subcommand() {
        // End of the chain: the hoist exists so this argv reaches the `status`
        // branch with its config, and so `tcp`'s own flags are parsed by the
        // tcp branch. Measured on Go v0.71.0 (both resolve; neither falls back
        // to run mode).
        match run_frpc(&["-c", "pA.toml", "status"]).expect("hoisted argv parses") {
            FrpcCmd::Status(args) => assert_eq!(args.config.as_deref(), Some("pA.toml")),
            other => panic!("expected the status command, got {other:?}"),
        }
        match run_frpc(&[
            "-c",
            "missing.toml",
            "tcp",
            "--local-port",
            "5",
            "--remote-port",
            "6",
            "--proxy-name",
            "x",
        ])
        .expect("hoisted argv parses")
        {
            FrpcCmd::Tcp(args) => {
                assert_eq!(args.local_port, 5);
                assert_eq!(args.remote_port, 6);
                assert_eq!(args.proxy_name.as_deref(), Some("x"));
            }
            other => panic!("expected the tcp command, got {other:?}"),
        }
        // A value that names a subcommand stays a value: this is run mode with
        // the config file `status`, not the admin command.
        match run_frpc(&["-c", "status"]).expect("run mode with a config named status") {
            FrpcCmd::Run(args) => assert_eq!(args.config, "status"),
            other => panic!("expected run mode, got {other:?}"),
        }
        // After a real `--`, the token is a positional, which run mode refuses
        // on frp-rs (Go ignores it and then fails to dial — the pre-existing
        // positional divergence recorded in § CLI inputs).
        assert!(run_frpc(&["-c", "pA.toml", "--", "status"]).is_err());
    }

    /// `FrpcCmd`'s twelve command variants, one per `frpc_parser` subcommand —
    /// the same set `FrpcCmd` in this file declares, and the same set
    /// [`FRPC_SUBCOMMANDS`] names. Adding a thirteenth subcommand to the parser
    /// without extending this list fails the match below.
    fn command_variant_name(cmd: &FrpcCmd) -> Option<&'static str> {
        match cmd {
            FrpcCmd::Tcp(_) => Some("tcp"),
            FrpcCmd::Udp(_) => Some("udp"),
            FrpcCmd::Http(_) => Some("http"),
            FrpcCmd::Https(_) => Some("https"),
            FrpcCmd::Stcp(_) => Some("stcp"),
            FrpcCmd::Xtcp(_) => Some("xtcp"),
            FrpcCmd::Sudp(_) => Some("sudp"),
            FrpcCmd::Tcpmux(_) => Some("tcpmux"),
            FrpcCmd::Verify(_) => Some("verify"),
            FrpcCmd::Reload(_) => Some("reload"),
            FrpcCmd::Status(_) => Some("status"),
            FrpcCmd::Stop(_) => Some("stop"),
            FrpcCmd::Run(_) => None,
        }
    }

    /// A command that needs a flag of its own when invoked bare: the parse
    /// fails, and the failure must name that flag (run mode has none of them,
    /// so this is the evidence that the branch was reached rather than fallen
    /// through to). `verify` needs `-c` (`verify`'s config is not optional in
    /// frp-rs); the other three admin commands complete with no flags.
    fn single_proxy_own_flag(name: &str) -> Option<&'static str> {
        match name {
            "tcp" | "udp" | "sudp" => Some("--local-port"),
            "http" | "https" => Some("--local-port"),
            "stcp" | "xtcp" => Some("--sk"),
            "tcpmux" => Some("--local-port"),
            "verify" => Some("--config"),
            _ => None,
        }
    }

    #[test]
    fn every_known_subcommand_name_selects_its_own_branch() {
        // Each name must actually reach its own branch. Two failure modes are
        // caught: a name with no `command("…")` in `frpc_parser` (run mode, or
        // a parse error), and a name that selects a *different* command.
        for name in FRPC_SUBCOMMANDS {
            assert_eq!(hoist(&[name]), [name], "{name} must be accepted as leading");
            let prepared = prepared_cli_argv(&[OsString::from(name)], RootCommand::Frpc);
            let own_flag = single_proxy_own_flag(name);
            match frpc_parser().to_options().run_inner(&prepared[..]) {
                // The four admin commands are complete without further flags.
                Ok(cmd) => assert_eq!(
                    command_variant_name(&cmd),
                    Some(name),
                    "{name} selected a different branch"
                ),
                Err(failure) => {
                    let own_flag = own_flag.unwrap_or_else(|| {
                        panic!("{name} must parse with no flags, got {failure:?}")
                    });
                    let message = failure.unwrap_stderr();
                    assert!(
                        message.contains(own_flag),
                        "{name} was not resolved: its own {own_flag} is not the error, got {message:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_known_subcommand_list_is_exactly_the_parser_branches() {
        // The other direction: `frpc_parser` composes one `command("…")` per
        // subcommand, and bpaf renders exactly those in its own help. Comparing
        // the list to that rendering fails if a branch is added to
        // `frpc_parser` without a name here (or removed from it while the name
        // stays), which is the drift a hand-written list otherwise allows.
        let failure = frpc_parser()
            .to_options()
            .run_inner(&["--help"][..])
            .expect_err("--help is reported as a ParseFailure");
        let text = match failure {
            bpaf::ParseFailure::Stdout(doc, _) => doc.to_string(),
            other => panic!("expected help on stdout, got {other:?}"),
        };
        let listed: Vec<String> = text
            .lines()
            .skip_while(|line| !line.trim_start().starts_with("Available commands:"))
            .skip(1)
            .take_while(|line| !line.trim().is_empty())
            .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
            .collect();
        assert_eq!(
            listed,
            FRPC_SUBCOMMANDS.to_vec(),
            "the parser's command list and FRPC_SUBCOMMANDS disagree; help was:\n{text}"
        );
    }

    /// The `frps` half of the pair above, in both directions, because
    /// [`FRPS_SUBCOMMANDS`] is a new hand-written list and the whole point of
    /// the list is that it matches [`frps_parser`].
    ///
    /// Forward: every name in the list must select a command branch — here
    /// `verify`, which parses with no further flags (Go registers `-c` with an
    /// empty default on `frps`, `cmd/frps/root.go:44`, so the command is
    /// complete bare). Reverse: the list must be exactly the `command("…")`
    /// branches bpaf renders for `frps_parser`.
    #[test]
    fn the_frps_command_list_is_exactly_the_parser_branches() {
        for name in FRPS_SUBCOMMANDS {
            match run_frps_cmd(&[name]) {
                Ok(FrpsCmd::Verify(args)) => assert_eq!(
                    args.config, "",
                    "{name} bare must mean \"no config file specified\", the empty default Go \
                     registers for `-c`"
                ),
                other => panic!("{name} must select the verify branch, got {other:?}"),
            }
        }

        let failure = frps_parser()
            .to_options()
            .run_inner(&["--help"][..])
            .expect_err("--help is reported as a ParseFailure");
        let text = match failure {
            bpaf::ParseFailure::Stdout(doc, _) => doc.to_string(),
            other => panic!("expected help on stdout, got {other:?}"),
        };
        let listed: Vec<String> = text
            .lines()
            .skip_while(|line| !line.trim_start().starts_with("Available commands:"))
            .skip(1)
            .take_while(|line| !line.trim().is_empty())
            .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
            .collect();
        assert_eq!(
            listed,
            FRPS_SUBCOMMANDS.to_vec(),
            "the parser's command list and FRPS_SUBCOMMANDS disagree; help was:\n{text}"
        );
    }

    /// Cobra's `stripFlags` reads **this root command's** flag registry, so the
    /// bool set is per root and the two sets are not interchangeable. Measured
    /// on Go v0.71.0 (`docs/developing.md` § CLI inputs carries the table):
    /// `frps --tls-only verify -c <cfg>`, `frps --enable-prometheus verify -c
    /// <cfg>` and `frps --disable-log-color verify -c <cfg>` all resolve
    /// `verify` (rc 0), so those three are pflag bools **on `frps`** — and the
    /// same three names are ordinary flags on `frpc`, where they would swallow
    /// a following token.
    ///
    /// The reverse-direction row is `--dashboard-tls-mode`: it looks like the
    /// other `--…-mode` flags but is registered with `VarP(BoolFuncFlag{…})`
    /// (`pkg/config/flags.go:256-258`), which never sets `NoOptDefVal`.
    /// Measured: `frps --dashboard-tls-mode verify -c <valid cfg>` consumes
    /// `verify` as the flag's value, finds no bare word and **starts the
    /// server** (killed by the 6 s probe watchdog at rc 143) instead of verifying. Treating it as
    /// a bool here would hoist `verify` out of that argv and turn a running
    /// server into a verify run.
    #[test]
    fn the_bool_root_flag_sets_are_per_root_command() {
        for keeps in [
            "--version",
            "-v",
            "--strict_config",
            "--strict-config",
            "--tls-only",
            "--tls_only",
            "--enable-prometheus",
            "--enable_prometheus",
            "--disable-log-color",
            "--disable_log_color",
        ] {
            assert!(
                !consumes_value(OsStr::new(keeps), RootCommand::Frps),
                "frps: {keeps} is a pflag bool (both spellings, through \
                 WordSepNormalizeFunc) and must not swallow the next token"
            );
        }
        for takes in [
            "--dashboard-tls-mode",
            "--dashboard_tls_mode",
            "--bind-port",
            "--bind_addr",
            "-p",
            "-t",
            "--token",
            "--allow-ports",
            "--log-file",
            "--config-dir",
            "--nodash",
            "--help",
            "-h",
        ] {
            assert!(
                consumes_value(OsStr::new(takes), RootCommand::Frps),
                "frps: {takes} must swallow the next token"
            );
        }

        // `frpc` is unchanged by this, and the three frps-only bools are
        // consumers there — which is what makes the sets per-root rather than
        // one shared constant.
        for takes in [
            "--tls-only",
            "--enable-prometheus",
            "--disable-log-color",
            "--dashboard-tls-mode",
            "--allow-ports",
        ] {
            assert!(
                consumes_value(OsStr::new(takes), RootCommand::Frpc),
                "frpc: {takes} is not a pflag bool on this root and must swallow"
            );
        }
        for keeps in ["--version", "--strict-config", "--strict_config", "-v"] {
            assert!(
                !consumes_value(OsStr::new(keeps), RootCommand::Frpc),
                "frpc: {keeps} is a pflag bool and must not swallow"
            );
        }
    }

    /// The `frps` hoist rows, each measured on Go v0.71.0 with its own config
    /// and port (`docs/developing.md` § CLI inputs). The command word moves past
    /// leading root flags exactly when cobra would have resolved it, and the
    /// first bare word is the only candidate:
    ///
    /// * `-c cfg.toml verify` and `--strict-config=false verify -c cfg.toml` —
    ///   the flag does not swallow it, so Go runs `verifyCmd` (rc 0); the base
    ///   binary answered rc 1 `` `verify` is not expected in this context ``;
    /// * `--tls-only` / `--enable-prometheus` / `--disable-log-color` /
    ///   `--version` / `--strict_config` before `verify` — all pflag bools, so
    ///   none of them consumes it (measured rc 0 on Go);
    /// * `-p 7000 verify` — `-p` takes a value, so `verify` is that value's
    ///   *successor* and no hoist happens;
    /// * `--dashboard-tls-mode verify` — that flag consumes `verify` itself, so
    ///   there is no command word at all (measured: Go starts the server);
    /// * `--strict-config true verify` — the space form: `true` is the first
    ///   bare word, and it is not a command, so `verify` is never reached
    ///   (measured: `unknown command "true" for "frps"`, rc 1).
    #[test]
    fn frps_hoists_verify_past_its_own_root_flags() {
        for flag in [
            "--strict-config=false",
            "--strict_config=false",
            "--tls-only",
            "--enable-prometheus",
            "--disable-log-color",
            "--version",
            "-v",
        ] {
            assert_eq!(
                hoist_frps(&[flag, "verify", "-c", "cfg.toml"]),
                ["verify", flag, "-c", "cfg.toml"],
                "frps {flag} is a pflag bool and must not swallow `verify`"
            );
        }
        assert_eq!(
            hoist_frps(&["-c", "cfg.toml", "verify"]),
            ["verify", "-c", "cfg.toml"]
        );
        assert_eq!(
            hoist_frps(&["-c", "cfg.toml", "--strict-config=false", "verify"]),
            ["verify", "-c", "cfg.toml", "--strict-config=false"]
        );
        // `-c cfg.toml verify --strict-config=false` (the flag after the
        // command) needs no hoist, and must not be rewritten either.
        assert_eq!(
            hoist_frps(&["verify", "-c", "cfg.toml", "--strict-config=false"]),
            ["verify", "-c", "cfg.toml", "--strict-config=false"]
        );

        // `-p 7000 verify`: `-p` takes a value, so the value is consumed and
        // `verify` — the *next* token — is the first bare word and is resolved.
        // Measured on Go v0.71.0 (rc 0).
        assert_eq!(
            hoist_frps(&["-p", "7000", "verify", "-c", "cfg.toml"]),
            ["verify", "-p", "7000", "-c", "cfg.toml"]
        );

        for unchanged in [
            // A value-taking flag swallows the command word itself: `verify` is
            // `-t`'s **value**, so no bare word survives...
            &["-t", "verify"][..],
            // ...and the same for the flag that only *looks* like a bool.
            &["--dashboard-tls-mode", "verify", "-c", "cfg.toml"][..],
            // The first bare word is `true`, which is not a command.
            &["--strict-config", "true", "verify", "-c", "cfg.toml"][..],
            // A real separator stops the scan.
            &["-c", "cfg.toml", "--", "verify"][..],
            // A config file literally named `verify` is a value, not a command.
            &["-c", "verify"][..],
            // Already leading.
            &["verify", "-c", "cfg.toml"][..],
            // A word that is not a command anywhere in the list.
            &["notacommand", "verify"][..],
        ] {
            assert_eq!(
                hoist_frps(unchanged),
                unchanged,
                "{unchanged:?} must not be rewritten on `frps`"
            );
        }
    }

    /// The end of the chain on `frps`: the hoisted argv must reach the `verify`
    /// branch with its config, which is the only reason the hoist exists (before
    /// it, this argv was rc 1 `` `verify` is not expected in this context ``).
    #[test]
    fn the_hoisted_frps_argv_parses_as_verify() {
        match run_frps_cmd(&["-c", "cfg.toml", "verify"]).expect("hoisted argv parses") {
            FrpsCmd::Verify(args) => {
                assert_eq!(args.config, "cfg.toml");
                assert!(args.strict_config);
            }
            other => panic!("expected the verify command, got {other:?}"),
        }
        match run_frps_cmd(&["--strict-config=false", "verify", "-c", "cfg.toml"])
            .expect("hoisted argv parses")
        {
            FrpsCmd::Verify(args) => {
                assert_eq!(args.config, "cfg.toml");
                assert!(!args.strict_config);
            }
            other => panic!("expected the verify command, got {other:?}"),
        }
        // `verify` without `-c` is the empty-path case, not a parse failure:
        // Go's `-c` default is the empty string on frps.
        match run_frps_cmd(&["verify"]).expect("bare verify parses") {
            FrpsCmd::Verify(args) => assert_eq!(args.config, ""),
            other => panic!("expected the verify command, got {other:?}"),
        }
        // A value that names the command stays a value: run mode with the config
        // file `verify`, never the verify command.
        match run_frps_cmd(&["-c", "verify"]).expect("run mode with a config named verify") {
            FrpsCmd::Run(args) => assert_eq!(args.config.as_deref(), Some("verify")),
            other => panic!("expected the frps run path, got {other:?}"),
        }
        // No `-c` at all is still the run path (the default `frps.toml`), not
        // `verify` — the two are separated by the command word, not by absence.
        match run_frps_cmd(&["--bind-port", "7000"]).expect("run mode parses") {
            FrpsCmd::Run(args) => assert_eq!(args.bind_port, Some(7000)),
            other => panic!("expected the frps run path, got {other:?}"),
        }
    }

    /// The two **frp-rs-only** `frps` root flags must not ride into `verify`,
    /// where Go's `frps` answers `unknown flag: …` with rc 1. They are the
    /// complete extension set, measured by diffing the two binaries' rendered
    /// `--help` flag lists: frp-rs-only = {`config-dir`, `log-format`}, with no
    /// Go-only flag left (the former Go-only `vhost-http-timeout` is now
    /// registered on `svr_transport`).
    ///
    /// Measured on Go v0.71.0, stdout 0 B and stderr 1 line + usage in both
    /// cases: `frps verify --log-format json -c <valid>` → rc **1** `Error:
    /// unknown flag: --log-format`; `frps verify --config-dir <dir> -c <valid>`
    /// → rc **1** `Error: unknown flag: --config-dir`. Before the
    /// [`FrpsRootSlots`] fix the first printed `syntax is ok` and exited **0** —
    /// a validation command reporting success for an argv Go rejects, exactly the
    /// reason `--config-dir` was refused from the start.
    ///
    /// `--log-format` is pinned in both directions: the run path still parses it
    /// (a documented extension there, used as `frps --log-format json -c <cfg>`),
    /// and the verify path refuses every spelling.
    #[test]
    fn frps_verify_refuses_the_run_paths_extension_flags() {
        assert_eq!(
            parse_frps_run(&["--log-format", "json"])
                .expect("the run path keeps the --log-format extension")
                .log_format
                .as_deref(),
            Some("json")
        );
        assert_eq!(
            parse_frps_run(&["--log_format", "json"])
                .expect("the underscore alias is the same run-path extension")
                .log_format
                .as_deref(),
            Some("json")
        );
        assert_eq!(
            parse_frps_run(&["--config-dir", "conf.d"])
                .expect("the run path keeps the --config-dir extension")
                .config_dir
                .as_deref(),
            Some("conf.d")
        );

        for args in [
            &["verify", "--log-format", "json", "-c", "x.toml"][..],
            &["verify", "--log_format", "json", "-c", "x.toml"][..],
            &["verify", "--log-format=json", "-c", "x.toml"][..],
            &["verify", "-c", "x.toml", "--log-format", "json"][..],
            &["verify", "--config-dir", "conf.d", "-c", "x.toml"][..],
            &["verify", "--config_dir", "conf.d", "-c", "x.toml"][..],
        ] {
            let err = run_frps_cmd(args)
                .expect_err(&format!("{args:?} must be refused on the verify path"))
                .unwrap_stderr();
            assert!(
                err.contains("is not expected in this context"),
                "{args:?} must be a leftover-token refusal naming the flag, got {err:?}"
            );
        }
    }
}

#[cfg(test)]
mod help_doc_tests {
    use super::*;

    /// Render the document the binary prints for `--help` on one surface.
    ///
    /// Goes through the same preparation and the same parsers the binaries use
    /// (`prepared_cli_argv`, then `run_inner`), and takes the `Doc` out of the
    /// `ParseFailure::Stdout` that `run_cli` intercepts — never through
    /// `run_cli` itself, which exits the test process.
    fn surface_document(root: RootCommand, command: Option<&str>) -> String {
        let mut argv: Vec<OsString> = Vec::new();
        if let Some(command) = command {
            argv.push(command.into());
        }
        argv.push("--help".into());
        let argv = prepared_cli_argv(&argv, root);
        let argv = &argv[..];
        let failure = match root {
            RootCommand::Frps => frps_parser()
                .to_options()
                .run_inner(bpaf::Args::from(argv))
                .err(),
            RootCommand::Frpc => frpc_parser()
                .to_options()
                .run_inner(bpaf::Args::from(argv))
                .err(),
        }
        .expect("--help must be reported as a ParseFailure");
        let bpaf::ParseFailure::Stdout(doc, _) = failure else {
            panic!("--help must be a Stdout failure: {failure:?}");
        };
        render_cobra_help(root, command, &doc)
    }

    /// Every surface this layer renders: `(label, root, command, rendered bytes,
    /// Go frp v0.71.0 bytes)` for the same command line.
    ///
    /// All fifteen are pinned by their **whole text** in `SURFACE_DOCUMENTS`,
    /// compared byte for byte by `every_surface_matches_its_whole_text_pin`; the
    /// byte counts here are the cheap first check that reports the sizes, and
    /// `pinned_surfaces_are_exactly_the_parsers_surfaces` holds the set itself to
    /// the parser's command set.
    ///
    /// Two of them are Go's document **byte for byte** — the `verify` pair, whose
    /// whole-text pins *are* the Go oracle constants and are additionally
    /// asserted against the render by
    /// `verify_documents_match_the_go_oracle_after_the_feature_adjustment`.
    /// The other thirteen are *stated replacements*: frp-rs renders cobra's shape
    /// over the flag surface its parser actually accepts, so it never advertises
    /// a flag or a shorthand it does not implement, and never hides one it does.
    ///
    /// Where the replacement is larger or smaller than Go's:
    ///
    /// - `frps`: `--config-dir`/`--log-format` are frp-rs-only, and frp-rs has no
    ///   `completion`/`help` built-in commands (Go's root lists both).
    /// - `frpc`: the five `--log-*`/`--disable-log-color` extensions, and no
    ///   `nathole`/`completion`/`help` command lines.
    /// - `frpc status|reload|stop`: `--admin-addr/-port/-user/-pwd` (plus `--json`
    ///   for `status`) are frp-rs-only; Go's admin commands have only
    ///   `--api-timeout`.
    /// - the eight proxy commands: every one prints Go's own flag **names** and
    ///   Go's shorthand for each flag frp-rs implements, but frp-rs implements a
    ///   smaller proxy flag set than Go (`--annotations`, `--bandwidth-limit*`,
    ///   `--client-id`, `--dns-server`, `--metadatas`, `--protocol`, `--tls-enable`,
    ///   `--user`, `--allow-users`, … have no frp-rs counterpart), and frp-rs adds
    ///   one row of its own (`--mux-port` on tcpmux); sudp's long-only
    ///   `--remote-port` is an frp-rs extension that reuses Go's tcp/udp row text.
    const SURFACES: [(&str, RootCommand, Option<&str>, usize, usize); 15] = [
        ("frps", RootCommand::Frps, None, 2467, 2394),
        ("frps verify", RootCommand::Frps, Some("verify"), 2103, 2103),
        ("frpc", RootCommand::Frpc, None, 1517, 1370),
        ("frpc tcp", RootCommand::Frpc, Some("tcp"), 992, 2211),
        ("frpc udp", RootCommand::Frpc, Some("udp"), 992, 2211),
        ("frpc http", RootCommand::Frpc, Some("http"), 1338, 2482),
        ("frpc https", RootCommand::Frpc, Some("https"), 1074, 2269),
        ("frpc stcp", RootCommand::Frpc, Some("stcp"), 1117, 2436),
        ("frpc xtcp", RootCommand::Frpc, Some("xtcp"), 1117, 2436),
        ("frpc sudp", RootCommand::Frpc, Some("sudp"), 1035, 2436),
        ("frpc tcpmux", RootCommand::Frpc, Some("tcpmux"), 1170, 2432),
        ("frpc verify", RootCommand::Frpc, Some("verify"), 543, 543),
        ("frpc reload", RootCommand::Frpc, Some("reload"), 801, 626),
        ("frpc status", RootCommand::Frpc, Some("status"), 859, 627),
        ("frpc stop", RootCommand::Frpc, Some("stop"), 789, 614),
    ];

    /// `frps verify --help` as Go frp v0.71.0 prints it (`/tmp` oracle, measured
    /// in the same session as the implementation).
    const GO_FRPS_VERIFY: &str = r##"Verify that the configures is valid

Usage:
  frps verify [flags]

Flags:
  -h, --help   help for verify

Global Flags:
      --allow-ports string               allow ports
      --allow-unsafe strings             allowed unsafe features, one or more of: TokenSourceExec
      --bind-addr string                 bind address (default "0.0.0.0")
  -p, --bind-port int                    bind port (default 7000)
  -c, --config string                    config file of frps
      --dashboard-addr string            dashboard address (default "0.0.0.0")
      --dashboard-port int               dashboard port
      --dashboard-pwd string             dashboard password (default "admin")
      --dashboard-tls-cert-file string   dashboard tls cert file
      --dashboard-tls-key-file string    dashboard tls key file
      --dashboard-tls-mode               if enable dashboard tls mode
      --dashboard-user string            dashboard user (default "admin")
      --disable-log-color                disable log color in console
      --enable-prometheus                enable prometheus dashboard
      --kcp-bind-port int                kcp bind udp port
      --log-file string                  log file (default "console")
      --log-level string                 log level (default "info")
      --log-max-days int                 log max days (default 3)
      --max-ports-per-client int         max ports per client
      --proxy-bind-addr string           proxy bind address (default "0.0.0.0")
      --quic-bind-port int               quic bind udp port
      --strict-config                    strict config parsing mode, unknown fields will cause errors (default true)
      --subdomain-host string            subdomain host
      --tls-only                         frps tls only
  -t, --token string                     auth token
  -v, --version                          version of frps
      --vhost-http-port int              vhost http port
      --vhost-http-timeout int           vhost http response header timeout (default 60)
      --vhost-https-port int             vhost https port
"##;

    /// `frpc verify --help` as Go frp v0.71.0 prints it.
    const GO_FRPC_VERIFY: &str = r##"Verify that the configures is valid

Usage:
  frpc verify [flags]

Flags:
  -h, --help   help for verify

Global Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc
"##;

    /// `frps --help` as the built binary prints it (2467 bytes).
    const FRPS_DOC: &str = r#"frps is the server of frp (https://github.com/fatedier/frp)

Usage:
  frps [flags]
  frps [command]

Available Commands:
  verify      Verify that the configures is valid

Flags:
      --allow-ports string               allow ports
      --allow-unsafe strings             allowed unsafe features, one or more of: TokenSourceExec
      --bind-addr string                 bind address (default "0.0.0.0")
  -p, --bind-port int                    bind port (default 7000)
  -c, --config string                    config file of frps
      --config-dir string                config directory, run one frps service for each file in config directory
      --dashboard-addr string            dashboard address (default "0.0.0.0")
      --dashboard-port int               dashboard port
      --dashboard-pwd string             dashboard password (default "admin")
      --dashboard-tls-cert-file string   dashboard tls cert file
      --dashboard-tls-key-file string    dashboard tls key file
      --dashboard-tls-mode               if enable dashboard tls mode
      --dashboard-user string            dashboard user (default "admin")
      --disable-log-color                disable log color in console
      --enable-prometheus                enable prometheus dashboard
  -h, --help                             help for frps
      --kcp-bind-port int                kcp bind udp port
      --log-file string                  log file (default "console")
      --log-format string                log format (default "text")
      --log-level string                 log level (default "info")
      --log-max-days int                 log max days (default 3)
      --max-ports-per-client int         max ports per client
      --proxy-bind-addr string           proxy bind address (default "0.0.0.0")
      --quic-bind-port int               quic bind udp port
      --strict-config                    strict config parsing mode, unknown fields will cause errors (default true)
      --subdomain-host string            subdomain host
      --tls-only                         frps tls only
  -t, --token string                     auth token
  -v, --version                          version of frps
      --vhost-http-port int              vhost http port
      --vhost-http-timeout int           vhost http response header timeout (default 60)
      --vhost-https-port int             vhost https port

Use "frps [command] --help" for more information about a command.
"#;

    /// `frpc --help` as the built binary prints it (1517 bytes).
    const FRPC_DOC: &str = r#"frpc is the client of frp (https://github.com/fatedier/frp)

Usage:
  frpc [flags]
  frpc [command]

Available Commands:
  http        Run frpc with a single http proxy
  https       Run frpc with a single https proxy
  reload      Hot-Reload frpc configuration
  status      Overview of all proxies status
  stcp        Run frpc with a single stcp proxy
  stop        Stop the running frpc
  sudp        Run frpc with a single sudp proxy
  tcp         Run frpc with a single tcp proxy
  tcpmux      Run frpc with a single tcpmux proxy
  udp         Run frpc with a single udp proxy
  verify      Verify that the configures is valid
  xtcp        Run frpc with a single xtcp proxy

Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --disable-log-color      disable log color in console
  -h, --help                   help for frpc
      --log-file string        log file (default "console")
      --log-format string      log format (default "text")
  -L, --log-level string       log level (default "info")
      --log-max-days int       log max days (default 3)
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc

Use "frpc [command] --help" for more information about a command.
"#;

    /// `frpc tcp --help` as the built binary prints it (992 bytes).
    const FRPC_TCP_DOC: &str = r#"Run frpc with a single tcp proxy

Usage:
  frpc tcp [flags]

Flags:
  -h, --help                 help for tcp
  -i, --local-ip string      local ip (default "127.0.0.1")
  -l, --local-port int       local port
  -n, --proxy-name string    proxy name
  -r, --remote-port int      remote port
  -s, --server-addr string   frp server's address (default "127.0.0.1")
  -P, --server-port int      frp server's port (default 7000)
  -t, --token string         auth token
      --uc                   use compression
      --ue                   use encryption

Global Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc
"#;

    /// `frpc udp --help` as the built binary prints it (992 bytes).
    const FRPC_UDP_DOC: &str = r#"Run frpc with a single udp proxy

Usage:
  frpc udp [flags]

Flags:
  -h, --help                 help for udp
  -i, --local-ip string      local ip (default "127.0.0.1")
  -l, --local-port int       local port
  -n, --proxy-name string    proxy name
  -r, --remote-port int      remote port
  -s, --server-addr string   frp server's address (default "127.0.0.1")
  -P, --server-port int      frp server's port (default 7000)
  -t, --token string         auth token
      --uc                   use compression
      --ue                   use encryption

Global Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc
"#;

    /// `frpc http --help` as the built binary prints it (1338 bytes).
    const FRPC_HTTP_DOC: &str = r#"Run frpc with a single http proxy

Usage:
  frpc http [flags]

Flags:
  -d, --custom-domain strings        custom domains
  -h, --help                         help for http
      --host-header-rewrite string   host header rewrite
      --http-pwd string              http auth password
      --http-user string             http auth user
  -i, --local-ip string              local ip (default "127.0.0.1")
  -l, --local-port int               local port
      --locations strings            locations
  -n, --proxy-name string            proxy name
      --sd string                    sub domain
  -s, --server-addr string           frp server's address (default "127.0.0.1")
  -P, --server-port int              frp server's port (default 7000)
  -t, --token string                 auth token
      --uc                           use compression
      --ue                           use encryption

Global Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc
"#;

    /// `frpc https --help` as the built binary prints it (1074 bytes).
    const FRPC_HTTPS_DOC: &str = r#"Run frpc with a single https proxy

Usage:
  frpc https [flags]

Flags:
  -d, --custom-domain strings   custom domains
  -h, --help                    help for https
  -i, --local-ip string         local ip (default "127.0.0.1")
  -l, --local-port int          local port
  -n, --proxy-name string       proxy name
      --sd string               sub domain
  -s, --server-addr string      frp server's address (default "127.0.0.1")
  -P, --server-port int         frp server's port (default 7000)
  -t, --token string            auth token
      --uc                      use compression
      --ue                      use encryption

Global Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc
"#;

    /// `frpc stcp --help` as the built binary prints it (1117 bytes).
    const FRPC_STCP_DOC: &str = r#"Run frpc with a single stcp proxy

Usage:
  frpc stcp [flags]

Flags:
  -h, --help                     help for stcp
  -i, --local-ip string          local ip (default "127.0.0.1")
  -l, --local-port int           local port
  -n, --proxy-name string        proxy name
  -s, --server-addr string       frp server's address (default "127.0.0.1")
  -P, --server-port int          frp server's port (default 7000)
      --sk string                secret key
      --tls-server-name string   specify the custom server name of tls certificate
  -t, --token string             auth token
      --uc                       use compression
      --ue                       use encryption

Global Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc
"#;

    /// `frpc xtcp --help` as the built binary prints it (1117 bytes).
    const FRPC_XTCP_DOC: &str = r#"Run frpc with a single xtcp proxy

Usage:
  frpc xtcp [flags]

Flags:
  -h, --help                     help for xtcp
  -i, --local-ip string          local ip (default "127.0.0.1")
  -l, --local-port int           local port
  -n, --proxy-name string        proxy name
  -s, --server-addr string       frp server's address (default "127.0.0.1")
  -P, --server-port int          frp server's port (default 7000)
      --sk string                secret key
      --tls-server-name string   specify the custom server name of tls certificate
  -t, --token string             auth token
      --uc                       use compression
      --ue                       use encryption

Global Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc
"#;

    /// `frpc sudp --help` as the built binary prints it (1035 bytes).
    const FRPC_SUDP_DOC: &str = r#"Run frpc with a single sudp proxy

Usage:
  frpc sudp [flags]

Flags:
  -h, --help                 help for sudp
  -i, --local-ip string      local ip (default "127.0.0.1")
  -l, --local-port int       local port
  -n, --proxy-name string    proxy name
      --remote-port int      remote port
  -s, --server-addr string   frp server's address (default "127.0.0.1")
  -P, --server-port int      frp server's port (default 7000)
      --sk string            secret key
  -t, --token string         auth token
      --uc                   use compression
      --ue                   use encryption

Global Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc
"#;

    /// `frpc tcpmux --help` as the built binary prints it (1170 bytes).
    const FRPC_TCPMUX_DOC: &str = r#"Run frpc with a single tcpmux proxy

Usage:
  frpc tcpmux [flags]

Flags:
  -d, --custom-domain strings   custom domains
  -h, --help                    help for tcpmux
  -i, --local-ip string         local ip (default "127.0.0.1")
  -l, --local-port int          local port
      --mux string              multiplexer
      --mux-port int            multiplexer port
  -n, --proxy-name string       proxy name
      --sd string               sub domain
  -s, --server-addr string      frp server's address (default "127.0.0.1")
  -P, --server-port int         frp server's port (default 7000)
  -t, --token string            auth token
      --uc                      use compression
      --ue                      use encryption

Global Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc
"#;

    /// `frpc reload --help` as the built binary prints it (801 bytes).
    const FRPC_RELOAD_DOC: &str = r#"Hot-Reload frpc configuration

Usage:
  frpc reload [flags]

Flags:
      --admin-addr string      admin address
      --admin-port int         admin port
      --admin-pwd string       admin password
      --admin-user string      admin user
      --api-timeout duration   Timeout for admin API calls (default 30s)
  -h, --help                   help for reload

Global Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc
"#;

    /// `frpc status --help` as the built binary prints it (859 bytes).
    const FRPC_STATUS_DOC: &str = r#"Overview of all proxies status

Usage:
  frpc status [flags]

Flags:
      --admin-addr string      admin address
      --admin-port int         admin port
      --admin-pwd string       admin password
      --admin-user string      admin user
      --api-timeout duration   Timeout for admin API calls (default 30s)
  -h, --help                   help for status
      --json                   Output the status as JSON

Global Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc
"#;

    /// `frpc stop --help` as the built binary prints it (789 bytes).
    const FRPC_STOP_DOC: &str = r#"Stop the running frpc

Usage:
  frpc stop [flags]

Flags:
      --admin-addr string      admin address
      --admin-port int         admin port
      --admin-pwd string       admin password
      --admin-user string      admin user
      --api-timeout duration   Timeout for admin API calls (default 30s)
  -h, --help                   help for stop

Global Flags:
      --allow-unsafe strings   allowed unsafe features, one or more of: TokenSourceExec
  -c, --config string          config file of frpc (default "./frpc.ini")
      --config-dir string      config directory, run one frpc service for each file in config directory
      --strict-config          strict config parsing mode, unknown fields will cause an errors (default true)
  -v, --version                version of frpc
"#;

    /// The exact stdout of every surface, in `SURFACES` order.
    ///
    /// The two `verify` entries are the Go oracle constants: those documents
    /// *are* Go's, byte for byte, so one text serves as both the oracle and the
    /// pin and appears exactly once in this file.
    ///
    /// This freezes the *usage text* as well as the flag names. Each row's usage
    /// string is a hand-written Go transcription (`GoFlagRow::usage`), which is
    /// intended for a compatibility surface: the document is a contract with Go's
    /// output, not a description the parser generates. A future flag addition,
    /// row re-wording or default change must therefore regenerate these constants
    /// from the rebuilt binaries and re-pin the byte count in `SURFACES` — the
    /// pins are the record, and the tests fail until they are updated.
    const SURFACE_DOCUMENTS: [&str; 15] = [
        FRPS_DOC,
        GO_FRPS_VERIFY,
        FRPC_DOC,
        FRPC_TCP_DOC,
        FRPC_UDP_DOC,
        FRPC_HTTP_DOC,
        FRPC_HTTPS_DOC,
        FRPC_STCP_DOC,
        FRPC_XTCP_DOC,
        FRPC_SUDP_DOC,
        FRPC_TCPMUX_DOC,
        GO_FRPC_VERIFY,
        FRPC_RELOAD_DOC,
        FRPC_STATUS_DOC,
        FRPC_STOP_DOC,
    ];

    /// `SURFACES` and `SURFACE_DOCUMENTS` are index-aligned, and both pairing
    /// loops use `.zip(...)`, which **truncates to the shorter list**. A sixteenth
    /// surface added to one table and not the other would therefore leave the new
    /// document entirely unpinned — and, in the reverse direction, a pin added
    /// without its surface row would never be rendered or checked. The length
    /// equality is asserted before both zips so the truncation cannot happen
    /// silently.
    fn assert_surface_tables_are_aligned() {
        assert_eq!(
            SURFACES.len(),
            SURFACE_DOCUMENTS.len(),
            "SURFACES and SURFACE_DOCUMENTS must be the same length; the `zip` in both \
             pairing loops truncates to the shorter list, leaving the extra surface unpinned"
        );
    }

    /// The whole-text pin for all 15 surfaces: the rendered document must equal
    /// the recorded stdout byte for byte. `SURFACE_DOCUMENTS` is generated
    /// mechanically from the built binaries (`frps --help`, `frpc tcp --help`,
    /// …), never retyped.
    ///
    /// This is the assertion; `every_surface_is_pinned_by_its_byte_count` stays
    /// alongside it as the cheap first check that reports the sizes.
    #[test]
    fn every_surface_matches_its_whole_text_pin() {
        assert_surface_tables_are_aligned();
        let mut mismatched: Vec<String> = Vec::new();
        for ((label, root, command, _, _), full) in SURFACES.into_iter().zip(SURFACE_DOCUMENTS) {
            let expected = feature_adjusted_pin(root, full);
            let document = surface_document(root, command);
            if document != expected {
                mismatched.push(format!(
                    "{label}: {} bytes (pinned {}) -- first difference: {}",
                    document.len(),
                    expected.len(),
                    first_difference(&expected, &document)
                ));
            }
        }
        assert!(
            mismatched.is_empty(),
            "the rendered documents changed; regenerate SURFACE_DOCUMENTS from the \
             built binaries:\n{}",
            mismatched.join("\n")
        );
    }

    /// A whole-text pin adjusted from the **full-feature** shape to the features
    /// this build actually compiled in.
    ///
    /// `SURFACE_DOCUMENTS` and [`GO_FRPS_VERIFY`] are the default-features
    /// record: `svr_transport` registers `--kcp-bind-port` under
    /// `#[cfg(feature = "kcp")]` and `--quic-bind-port` under
    /// `#[cfg(feature = "quic")]`, so with the default features on the `frps`
    /// and `frps verify` documents each carry those two rows. A build without a
    /// feature cannot render its row, so the expected document is the pin
    /// **minus exactly that one line**.
    ///
    /// Nothing else is relaxed: every other byte still comes from the frozen
    /// constant, so the default-features lane compares against the pin unchanged
    /// and any other change to a rendered document still fails. Only the `frps`
    /// pins carry those rows (`frpc` never renders them, and [`FRPC_DOC`] etc.
    /// have none), so a `frpc` pin is returned untouched.
    fn feature_adjusted_pin(root: RootCommand, full: &str) -> String {
        if root != RootCommand::Frps {
            return full.to_owned();
        }
        let mut expected = full.to_owned();
        for (enabled, long) in [
            (cfg!(feature = "kcp"), "--kcp-bind-port"),
            (cfg!(feature = "quic"), "--quic-bind-port"),
        ] {
            if enabled {
                continue;
            }
            expected = strip_pinned_row(&expected, long);
        }
        expected
    }

    /// `document` without the row whose long flag is exactly `long`, byte for byte.
    ///
    /// Panics unless **exactly one** line carries that long flag. The caller only
    /// asks for a row the full-feature pin is known to carry, so zero matches mean
    /// the pin and the feature gate have drifted apart, and two mean the pin
    /// renders the row twice and dropping one of them would leave the expectation
    /// silently wrong.
    fn strip_pinned_row(document: &str, long: &str) -> String {
        let mut stripped = String::with_capacity(document.len());
        let mut removed = 0usize;
        for line in document.split_inclusive('\n') {
            if row_long_flag(line) == Some(long) {
                removed += 1;
            } else {
                stripped.push_str(line);
            }
        }
        assert_eq!(
            removed, 1,
            "the full-feature pin must carry exactly one `{long}` row, found {removed}"
        );
        stripped
    }

    /// The long flag of one rendered pflag row, if `line` is a row at all:
    /// `--config` for both `  -c, --config string    config file` and
    /// `      --config string         config file`, `None` for a heading, a blank
    /// line, a wrapped usage continuation, or cobra's footer.
    ///
    /// The non-panicking sibling of [`split_row`]: rows are indented two spaces
    /// (a shorthand is printed) or six (it is not) and the grid separates the head
    /// from the usage text with a run of spaces, so the head is everything before
    /// the first two-space gap. The long flag is the `--…` word of that head,
    /// compared as a whole token — which is what keeps `--config` from matching
    /// `--config-dir`.
    ///
    /// All three shapes are required, and each is load-bearing: the indent pins
    /// the row grid (a wrapped continuation is indented to the usage column, far
    /// past six), the leading `-` rejects `Usage:`/`Available Commands:` rows, and
    /// the grid gap rejects cobra's footer
    /// `Use "frps [command] --help" for more information about a command.` — that
    /// sentence contains `--help` and starts in column zero, so without the indent
    /// and gap checks it reads as a `--help` row.
    fn row_long_flag(line: &str) -> Option<&str> {
        let start = line.len() - line.trim_start().len();
        if start != 2 && start != 6 {
            return None;
        }
        let trimmed = line.trim_start();
        if !trimmed.starts_with('-') {
            return None;
        }
        let gap = trimmed.find("  ")?;
        let head = &trimmed[..gap];
        head.split_whitespace().find(|word| word.starts_with("--"))
    }

    /// [`row_long_flag`] is the only reader of the rendered grid, so its three
    /// shape guards are pinned directly: the 2/6 indent, the leading `-`, and the
    /// two-space grid gap. Each assertion is a shape that a weaker reader (the
    /// `start > 6` this replaced, or a `> 60` weakening of it) would misread.
    #[test]
    fn row_long_flag_requires_a_row_indent_a_leading_dash_and_a_grid_gap() {
        assert_eq!(
            row_long_flag("  -c, --config string    config file of frpc\n"),
            Some("--config")
        );
        assert_eq!(
            row_long_flag("      --config string         config file of frpc\n"),
            Some("--config")
        );
        // Not a row: too deep (a wrapped usage continuation), too shallow (prose),
        // no leading dash (a `Usage:`/`Available Commands:` row), no grid gap.
        assert_eq!(
            row_long_flag("            --config string         config file\n"),
            None,
            "a 12-space indent is a wrapped continuation, not a row"
        );
        assert_eq!(row_long_flag("--config string    config file\n"), None);
        assert_eq!(row_long_flag("  Usage:\n  frpc tcpmux [flags]\n"), None);
        // The shape the leading-`-` guard rejects *by itself*: a line at a
        // row-like indent with a two-space grid gap whose head still carries a
        // `--…` token. The `Usage:` rows above do not red when the guard is
        // deleted (their head ends before any flag), and neither does the footer
        // below (column zero already fails the indent guard), so this probe is
        // what pins the guard.
        assert_eq!(
            row_long_flag("  Use \"frps --help\"  for more information about a command.\n"),
            None,
            "prose at a row-like indent that mentions a --flag is not a row"
        );
        assert_eq!(row_long_flag("  -c, --config=config file\n"), None);
        // cobra's footer, verbatim from FRPS_DOC/FRPC_DOC: it mentions `--help`
        // but is not a row, and `strip_pinned_row(doc, "--help")` must not take it.
        assert_eq!(
            row_long_flag("Use \"frps [command] --help\" for more information about a command.\n"),
            None,
            "cobra's footer is not a flag row"
        );
        assert_eq!(row_long_flag("\n"), None);
        assert_eq!(row_long_flag("Flags:\n"), None);
        assert_eq!(row_long_flag(""), None);
    }

    /// A row is taken by its long-flag **token**, not by prefix, and exactly one
    /// row is taken: `frps` renders both `--config` and `--config-dir`, and a
    /// prefix match would strip the wrong one.
    #[test]
    fn stripping_a_row_matches_the_long_token_and_takes_exactly_one() {
        let document = "      --config string         config file\n\
                        \x20     --config-dir string     config directory\n";
        assert_eq!(
            strip_pinned_row(document, "--config"),
            "      --config-dir string     config directory\n"
        );
        assert_eq!(
            strip_pinned_row(document, "--config-dir"),
            "      --config string         config file\n"
        );
    }

    /// [`strip_pinned_row`] must **count**, not merely find. The two directions
    /// fail differently, and only one of them can see the `>= 1` weakening: with
    /// 0 matches the stronger `assert_eq!(removed, 1)` and the weaker
    /// `assert!(removed >= 1)` both panic, so the **missing-row** pin catches only
    /// dropping or inverting the count, while the `>= 1` weakening itself is
    /// caught by the **duplicated-row** pin (2 matches), where it passes and
    /// silently strips the row twice. Both directions are pinned as panics.
    #[test]
    #[should_panic(expected = "must carry exactly one `--config` row, found 0")]
    fn strip_pinned_row_panics_on_a_missing_row() {
        strip_pinned_row(
            "      --config-dir string     config directory\n",
            "--config",
        );
    }

    #[test]
    #[should_panic(expected = "must carry exactly one `--config` row, found 2")]
    fn strip_pinned_row_panics_on_a_duplicated_row() {
        strip_pinned_row(
            "      --config string    config file\n      --config string    config file\n",
            "--config",
        );
    }

    /// Where a rendered document left its pin: the first line that differs, or
    /// the line/byte-count gap when one text is a prefix of the other.
    fn first_difference(expected: &str, actual: &str) -> String {
        for (index, (pinned, rendered)) in expected.lines().zip(actual.lines()).enumerate() {
            if pinned != rendered {
                return format!(
                    "line {}: pinned `{pinned}`, rendered `{rendered}`",
                    index + 1
                );
            }
        }
        format!(
            "{} bytes / {} lines pinned, {} bytes / {} lines rendered",
            expected.len(),
            expected.lines().count(),
            actual.len(),
            actual.lines().count()
        )
    }

    /// The two `verify` surfaces are the ones whose pin **is** Go's own document,
    /// so this asserts them against the Go v0.71.0 oracle directly — through the
    /// same feature adjustment every other pin gets, because the oracle, too, is
    /// the full-feature shape and a build without `kcp`/`quic` cannot render the
    /// two `Global Flags` rows Go prints there.
    ///
    /// `frpc` renders neither row, so [`feature_adjusted_pin`] is the identity for
    /// it and the `frpc` half below is Go's stdout **verbatim in every feature
    /// shape**. The `frps` half is Go's stdout byte for byte whenever `kcp` and
    /// `quic` are both compiled in (frp-core's default), and Go's document minus
    /// exactly those two rows otherwise.
    ///
    /// The assertion that makes the two **oracle texts** falsifiable is the loop
    /// below: `GO_FRPS_VERIFY` must actually carry both gated rows (or
    /// `feature_adjusted_pin` would be stripping nothing and the feature-shape path
    /// would be dead), and `GO_FRPC_VERIFY` must carry neither (or the frpc claim
    /// would be an unexamined assumption rather than a fact about the data).
    /// `feature_adjusted_pin` itself is pinned on a synthetic document by
    /// [`feature_adjusted_pin_strips_exactly_the_rows_this_build_cannot_render`].
    #[test]
    fn verify_documents_match_the_go_oracle_after_the_feature_adjustment() {
        assert_eq!(
            surface_document(RootCommand::Frps, Some("verify")),
            feature_adjusted_pin(RootCommand::Frps, GO_FRPS_VERIFY),
            "frps verify --help must be Go's document, byte for byte, once only the rows \
             this build cannot render are removed"
        );
        for long in ["--kcp-bind-port", "--quic-bind-port"] {
            assert!(
                GO_FRPS_VERIFY
                    .lines()
                    .any(|line| row_long_flag(line) == Some(long)),
                "frps's oracle must carry {long}, or feature_adjusted_pin strips nothing \
                 and this test never exercises the feature-shape path"
            );
            assert!(
                GO_FRPC_VERIFY
                    .lines()
                    .all(|line| row_long_flag(line) != Some(long)),
                "frpc's oracle must not carry {long}: the frpc path is never adjusted"
            );
        }
        // A former assertion here was `feature_adjusted_pin(Frpc, GO_FRPC_VERIFY) ==
        // GO_FRPC_VERIFY`. It only restated the helper's first line (`if root !=
        // RootCommand::Frps { return full.to_owned(); }`) and could not fail. The
        // contract it was reaching for is pinned on a synthetic document, in every
        // feature shape, by
        // `feature_adjusted_pin_strips_exactly_the_rows_this_build_cannot_render`.
        assert_eq!(
            surface_document(RootCommand::Frpc, Some("verify")),
            GO_FRPC_VERIFY,
            "frpc verify --help must be Go's document, byte for byte, in every feature shape"
        );
    }

    /// `feature_adjusted_pin`'s contract, pinned on a synthetic document so the
    /// assertion holds in every feature shape: it must drop each feature-gated row
    /// exactly when that feature is off, must leave every unrelated row alone, and
    /// must never touch a non-`frps` pin.
    ///
    /// This is what replaces the former vacuous identity. With the helper stripping
    /// a row whose feature is *on* it fails here; in the `kcp`-less / `quic`-less
    /// shapes (`.github/workflows/ci.yml`'s feature-split lanes) it also fails if the
    /// helper stops stripping at all — the two mutants the identity could not see.
    #[test]
    fn feature_adjusted_pin_strips_exactly_the_rows_this_build_cannot_render() {
        let synthetic = concat!(
            "      --kcp-bind-port int          kcp bind port\n",
            "      --quic-bind-port int         quic bind port\n",
            "      --other string               untouched\n",
        );
        let adjusted = feature_adjusted_pin(RootCommand::Frps, synthetic);
        for (enabled, long) in [
            (cfg!(feature = "kcp"), "--kcp-bind-port"),
            (cfg!(feature = "quic"), "--quic-bind-port"),
        ] {
            assert_eq!(
                adjusted.contains(long),
                enabled,
                "feature_adjusted_pin must keep {long} exactly when its feature is on"
            );
        }
        assert!(
            adjusted.contains("--other"),
            "feature_adjusted_pin must leave unrelated rows alone"
        );
        assert_eq!(
            feature_adjusted_pin(RootCommand::Frpc, synthetic),
            synthetic,
            "frpc renders no feature-gated row, so its pin must never be adjusted"
        );
    }

    #[test]
    fn every_surface_is_pinned_by_its_byte_count() {
        assert_surface_tables_are_aligned();
        let mut mismatched: Vec<String> = Vec::new();
        for ((label, root, command, rendered, go), full) in
            SURFACES.into_iter().zip(SURFACE_DOCUMENTS)
        {
            let expected = feature_adjusted_pin(root, full);
            // `rendered` pins the full-feature document; a feature-adjusted pin
            // is that many bytes shorter, so the count shrinks with it.
            let expected_len = rendered - (full.len() - expected.len());
            let document = surface_document(root, command);
            if document.len() != expected_len {
                mismatched.push(format!(
                    "{label}: {} bytes, this build expects {expected_len} \
                     (the full-feature pin is {rendered} bytes, Go v0.71.0 {go})",
                    document.len()
                ));
            }
        }
        assert!(
            mismatched.is_empty(),
            "the rendered documents changed size; re-measure and update SURFACES:\n{}",
            mismatched.join("\n")
        );
    }

    /// The pinned surface set is exactly the parser's own command set: the root
    /// document plus every subcommand [`RootCommand::subcommands`] resolves, each
    /// pinned exactly once.
    ///
    /// `subcommands()` is already pinned against the parser in both directions
    /// (`the_known_subcommand_list_is_exactly_the_parser_branches`,
    /// `the_frps_command_list_is_exactly_the_parser_branches`) and against the
    /// rendered `Available Commands:` by
    /// `available_commands_are_the_implemented_ones_only`, so this closes the last
    /// gap: a subcommand the parser grows but `SURFACES` never pins — or pins
    /// twice — now fails here instead of quietly leaving the new document
    /// unpinned.
    #[test]
    fn pinned_surfaces_are_exactly_the_parsers_surfaces() {
        for root in [RootCommand::Frps, RootCommand::Frpc] {
            let mut pinned: Vec<Option<&str>> = SURFACES
                .iter()
                .filter(|(_, surface_root, ..)| *surface_root == root)
                .map(|(_, _, command, ..)| *command)
                .collect();
            pinned.sort_unstable();
            let mut expected: Vec<Option<&str>> = std::iter::once(None)
                .chain(root.subcommands().iter().copied().map(Some))
                .collect();
            expected.sort_unstable();
            assert_eq!(
                pinned, expected,
                "{root:?}: SURFACES must pin the root document and every subcommand \
                 exactly once"
            );
        }
    }

    /// Split one pflag row into `(head, long, usage)`: `head` is the flag token
    /// with its shorthand and varname, `long` the long name without dashes.
    fn split_row(line: &str) -> (String, String, String) {
        let start = line.len() - line.trim_start().len();
        let gap = start
            + line[start..]
                .find("   ")
                .expect("pflag always leaves at least a three-space gap");
        let head = line[..gap].trim_end();
        let usage = line[gap..].trim_start();
        let long = head
            .split_whitespace()
            .find(|word| word.starts_with("--"))
            .expect("every rendered row names a long flag")
            .trim_start_matches('-')
            .to_string();
        (head.to_string(), long, usage.to_string())
    }

    /// The rows under a `Flags:` / `Global Flags:` heading.
    fn section_rows(document: &str, heading: &str) -> Vec<(String, String, String)> {
        let mut rows = Vec::new();
        let mut inside = false;
        for line in document.lines() {
            if line == heading {
                inside = true;
                continue;
            }
            if !inside {
                continue;
            }
            if line.is_empty() || !line.starts_with(' ') {
                break;
            }
            rows.push(split_row(line));
        }
        rows
    }

    fn printed_short(head: &str) -> Option<char> {
        let rest = head.trim_start().strip_prefix('-')?;
        if rest.starts_with('-') {
            return None;
        }
        rest.chars().next()
    }

    /// The item's second requirement: a bool flag built by `go_bool_flag_impl!`
    /// is a bpaf `Or` of an `Argument` and a `Flag`, which bpaf's own renderer
    /// prints as two rows (`--strict-config=BOOL` and `--strict-config`). Cobra
    /// prints one. No `=` may survive, no long name may appear twice, and each
    /// section is sorted by long name.
    #[test]
    fn bool_flags_collapse_to_one_row_each() {
        for (label, root, command, _, _) in SURFACES {
            let document = surface_document(root, command);
            let mut seen: Vec<String> = Vec::new();
            for heading in ["Flags:", "Global Flags:"] {
                let mut longs: Vec<String> = section_rows(&document, heading)
                    .into_iter()
                    .map(|(head, long, _)| {
                        assert!(
                            !head.contains('='),
                            "{label}: bpaf's `{head}` spelling survived the bool collapse"
                        );
                        long
                    })
                    .collect();
                let mut sorted = longs.clone();
                sorted.sort();
                assert_eq!(
                    longs, sorted,
                    "{label}: {heading} rows are not sorted by long name"
                );
                longs.dedup();
                seen.append(&mut longs);
            }
            let mut unique = seen.clone();
            unique.sort();
            unique.dedup();
            assert_eq!(
                seen.len(),
                unique.len(),
                "{label}: a flag is rendered more than once: {seen:?}"
            );
            assert!(
                !document.contains("=BOOL")
                    && !document.contains("=FILE")
                    && !document.contains("=DIR"),
                "{label}: a bpaf `--flag=VALUE` row survived"
            );
        }
        assert_eq!(
            surface_document(RootCommand::Frps, None)
                .matches("--strict-config")
                .count(),
            1,
            "frps --strict-config must be one row, not bpaf's two"
        );
    }

    /// No flag may render without a description: the renderer has no fallback to
    /// bpaf's own text, so a new flag added to a parser but not to a text table
    /// must fail here rather than ship an empty row.
    #[test]
    fn every_rendered_flag_has_a_usage_text() {
        let mut missing: Vec<String> = Vec::new();
        for (label, root, command, _, _) in SURFACES {
            let document = surface_document(root, command);
            for heading in ["Flags:", "Global Flags:"] {
                for (head, _, usage) in section_rows(&document, heading) {
                    if usage.is_empty() {
                        missing.push(format!("{label}: `{}`", head.trim()));
                    }
                }
            }
        }
        assert!(
            missing.is_empty(),
            "these flags render with no usage text (add a GoFlagRow to the text tables): {missing:#?}"
        );
    }

    /// A leaf's inherited flags are exactly the root's persistent set, and the
    /// root itself has no `Global Flags:` section — cobra's rule, and the reason
    /// `frps verify` can be Go's document byte for byte.
    #[test]
    fn leaf_global_flags_are_the_root_persistent_flags() {
        for (label, root, command, _, _) in SURFACES {
            let document = surface_document(root, command);
            let globals: Vec<String> = section_rows(&document, "Global Flags:")
                .into_iter()
                .map(|(_, long, _)| long)
                .collect();
            if command.is_none() {
                assert!(
                    globals.is_empty() && !document.contains("Global Flags:"),
                    "{label}: the root command must not have a Global Flags section"
                );
                continue;
            }
            let mut expected: Vec<String> = root_persistent_flags(root)
                .iter()
                .map(|row| row.long.replace('_', "-"))
                .collect();
            expected.sort();
            assert_eq!(
                globals, expected,
                "{label}: inherited flags must be exactly the root's persistent flags"
            );
            let locals: Vec<String> = section_rows(&document, "Flags:")
                .into_iter()
                .map(|(_, long, _)| long)
                .collect();
            let mut local_sorted = locals.clone();
            local_sorted.sort();
            assert!(
                !locals.iter().any(|long| expected.contains(long)),
                "{label}: a persistent flag is also rendered as a local one"
            );
            assert_eq!(locals, local_sorted);
        }
    }

    /// Cobra adds `-h, --help` to every command, with `help for <its own name>`.
    /// bpaf's help flag lives in its `Info`, not in the parser metadata, so the
    /// renderer synthesizes it — exactly once, in `Flags:`.
    #[test]
    fn help_row_is_synthesized_for_every_command() {
        for (label, root, command, _, _) in SURFACES {
            let document = surface_document(root, command);
            let name = command.unwrap_or_else(|| root_name(root));
            let rows = section_rows(&document, "Flags:");
            let help: Vec<&(String, String, String)> =
                rows.iter().filter(|(_, long, _)| long == "help").collect();
            assert_eq!(help.len(), 1, "{label}: exactly one help row");
            assert_eq!(help[0].0.trim_start(), "-h, --help");
            assert_eq!(help[0].2, format!("help for {name}"));
            assert!(
                section_rows(&document, "Global Flags:")
                    .iter()
                    .all(|(_, long, _)| long != "help"),
                "{label}: the help flag is local to every command, never inherited"
            );
        }
    }

    /// `Available Commands:` lists exactly the subcommands frp-rs implements, in
    /// cobra's sorted order — never Go's `completion`/`help` built-ins or the
    /// unimplemented `nathole`.
    #[test]
    fn available_commands_are_the_implemented_ones_only() {
        for (root, name) in [(RootCommand::Frps, "frps"), (RootCommand::Frpc, "frpc")] {
            let document = surface_document(root, None);
            let commands: Vec<&str> = document
                .lines()
                .skip_while(|line| *line != "Available Commands:")
                .skip(1)
                .take_while(|line| !line.is_empty())
                .map(|line| {
                    line.split_whitespace()
                        .next()
                        .expect("a command row has a name")
                })
                .collect();
            let mut expected: Vec<&str> = root.subcommands().to_vec();
            expected.sort_unstable();
            assert_eq!(
                commands, expected,
                "{name}: Available Commands must be exactly the implemented subcommands"
            );
            for builtin in ["completion", "help", "nathole"] {
                assert!(
                    !commands.contains(&builtin),
                    "{name} must not advertise the unimplemented `{builtin}`"
                );
            }
        }
    }

    /// The surface bpaf resolves is the surface the document describes; `--help
    /// <word>` is Go's root help, `--help=true <word>` the subcommand's.
    #[test]
    fn help_request_resolves_the_surface_cobra_resolves() {
        let request = |args: &[&str]| {
            let argv: Vec<OsString> = args.iter().map(Into::into).collect();
            let prepared = prepared_cli_argv(&argv, RootCommand::Frpc);
            help_request(RootCommand::Frpc, &prepared).command
        };
        assert_eq!(request(&["--help"]), None);
        assert_eq!(request(&["status", "--help"]), Some("status"));
        assert_eq!(request(&["--help=true", "status"]), Some("status"));
        // Go prints the root document here too: `--help` consumes the next token.
        assert_eq!(request(&["--help", "status"]), None);
        assert_eq!(request(&["status", "-h"]), Some("status"));
    }

    /// Where the parser has a shorthand it is Go's; where frp-rs never
    /// implemented Go's shorthand the document must not print it (Go's rows are
    /// an invariant to check, never the value to print).
    #[test]
    fn parser_shorthands_agree_with_go_where_the_parser_has_one() {
        for (label, root, command, _, _) in SURFACES {
            let document = surface_document(root, command);
            let tables = help_flag_tables(root, command);
            for heading in ["Flags:", "Global Flags:"] {
                for (head, long, _) in section_rows(&document, heading) {
                    let Some(printed) = printed_short(&head) else {
                        continue;
                    };
                    // `-h, --help` is synthesized per command; it is not one of
                    // Go's flag rows (which the tables deliberately exclude).
                    if long == "help" {
                        continue;
                    }
                    let go = go_flag_row(&tables, &long);
                    assert_eq!(
                        Some(printed),
                        go.and_then(|row| row.short),
                        "{label}: --{long} prints -{printed}, Go has {:?}",
                        go.and_then(|row| row.short)
                    );
                }
            }
        }
        // The whole `frpc tcp` short set, spelled out: Go registers `-i`, `-l`,
        // `-r`, `-s`, `-P`, `-n` and `-t` on this command, and Go's two proxy
        // bools (`uc`/`ue`) print no shorthand at all. This is the pin that would
        // red if a shorthand were dropped, renamed, or attached to the wrong row;
        // the loop above only checks rows that already print one.
        let tcp = surface_document(RootCommand::Frpc, Some("tcp"));
        let expected: Vec<(&str, Option<char>)> = vec![
            ("local-ip", Some('i')),
            ("local-port", Some('l')),
            ("proxy-name", Some('n')),
            ("remote-port", Some('r')),
            ("server-addr", Some('s')),
            ("server-port", Some('P')),
            ("token", Some('t')),
            ("uc", None),
            ("ue", None),
        ];
        let rendered: Vec<(String, Option<char>)> = section_rows(&tcp, "Flags:")
            .into_iter()
            .filter(|(_, long, _)| long != "help")
            .map(|(head, long, _)| (long, printed_short(&head)))
            .collect();
        let expected: Vec<(String, Option<char>)> = expected
            .into_iter()
            .map(|(name, short)| (name.to_string(), short))
            .collect();
        assert_eq!(
            rendered, expected,
            "frpc tcp must render Go's seven shorthanded rows plus the two unshorthanded bools"
        );
    }

    /// True when `help_flag_tables` lists `key`'s table for this surface — the
    /// tables are identified by their first row's `long`, which is unique among
    /// them (`config-dir`, `log-file`, `admin-addr`, `mux-port`, `allow-users`,
    /// `--allow-unsafe`'s `allow-unsafe`, …).
    fn surface_consults(root: RootCommand, command: Option<&str>, key: &str) -> bool {
        help_flag_tables(root, command)
            .into_iter()
            .any(|table| table.first().is_some_and(|row| row.long == key))
    }

    /// Every row of every **extension** table describes a flag frp-rs implements,
    /// so it must be rendered by at least one surface that consults that table.
    ///
    /// This is what makes the extension tables' data *live*: before it, a bogus
    /// `GoFlagRow` added to `FRPC_PROXY_EXTENSION_FLAGS` (or `FRPS_EXTENSION_FLAGS`)
    /// was consulted by no assertion at all, so every test in this module stayed
    /// green. The Go tables are the opposite case — they carry rows for flags
    /// frp-rs has no flag for at all, which are deliberately never rendered; those
    /// live rows are pinned by `the_go_only_proxy_rows_are_exactly_the_recorded_set`.
    #[test]
    fn every_extension_table_row_is_rendered_by_a_surface_that_consults_it() {
        let rendered: Vec<(&str, std::collections::BTreeSet<String>)> = SURFACES
            .into_iter()
            .map(|(label, root, command, _, _)| {
                let longs = surface_document(root, command)
                    .lines()
                    .filter_map(row_long_flag)
                    .map(|long| long.trim_start_matches("--").to_owned())
                    .collect();
                (label, longs)
            })
            .collect();
        for table in [
            FRPS_EXTENSION_FLAGS,
            FRPC_ROOT_EXTENSION_FLAGS,
            FRPC_ADMIN_EXTENSION_FLAGS,
            FRPC_PROXY_EXTENSION_FLAGS,
        ] {
            let rows: Vec<&str> = table.iter().map(|row| row.long).collect();
            let key = rows[0];
            let labels: Vec<&str> = SURFACES
                .into_iter()
                .filter(|(_, root, command, _, _)| surface_consults(*root, *command, key))
                .map(|(label, ..)| label)
                .collect();
            assert!(
                !labels.is_empty(),
                "extension table {rows:?} is consulted by no surface in SURFACES"
            );
            for row in table {
                assert!(
                    SURFACES
                        .into_iter()
                        .filter(|(_, root, command, _, _)| surface_consults(*root, *command, key))
                        .any(|(label, ..)| rendered
                            .iter()
                            .find(|(candidate, _)| *candidate == label)
                            .is_some_and(|(_, longs)| longs.contains(row.long))),
                    "extension table {rows:?} carries `{}`, but none of the surfaces that \
                     consult it ({labels:?}) renders that row: the row is unreachable data",
                    row.long
                );
            }
        }
    }

    /// The `FRPC_PROXY_GO_FLAGS` rows frp-rs's eight proxies do **not** implement:
    /// Go v0.71.0's own proxy rows that have no frp-rs flag at all. Nothing renders
    /// them, so no other assertion in this module is falsified by editing them —
    /// this explicit set is the only pin on their `long`s.
    ///
    /// This is a **union** across the eight surfaces, so on its own it is blind to
    /// a row that one surface dropped while another still renders it (which is how
    /// `proxy-name` once counted as implemented via sudp alone). The per-surface
    /// complement is pinned separately by
    /// [`every_proxy_surface_renders_exactly_the_go_rows_that_surface_implements`].
    ///
    /// RESIDUE: these rows render nothing, so their `long`s are pinned here and
    /// their `short`/`varname`/`usage` cells by [`GO_ONLY_PROXY_ROW_TEXT`].
    /// Without that table they were the "inert pin data" class: `SURFACES`
    /// carries only Go's *byte count*, not its text, so re-wording a row's
    /// hand-transcribed help left every test green. Every *rendered* row's text,
    /// by contrast, is pinned byte for byte by the `FRPC_*_DOC` whole-text
    /// constants.
    const GO_ONLY_PROXY_ROWS: [&str; 14] = [
        "allow-users",
        "annotations",
        "bandwidth-limit",
        "bandwidth-limit-mode",
        "client-id",
        "disable-log-color",
        "dns-server",
        "log-file",
        "log-level",
        "log-max-days",
        "metadatas",
        "protocol",
        "tls-enable",
        "user",
    ];

    /// The byte-exact witness for the [`FRPC_PROXY_GO_FLAGS`] rows frp-rs never
    /// renders ([`GO_ONLY_PROXY_ROWS`]) — `(long, short, varname, usage)`, in the
    /// table's own pflag byte order.
    ///
    /// These cells are hand-transcribed Go v0.71.0 help text that no other
    /// assertion reads, so this table is their only witness: it freezes the
    /// transcription, making a change deliberate and reviewable against the Go
    /// binary instead of a silent drift. It is *not* a parity oracle — the Go
    /// binary stays out of the build — so a wrong transcription is preserved
    /// here until it is re-measured.
    const GO_ONLY_PROXY_ROW_TEXT: [(&str, Option<char>, Option<&str>, &str); 14] = [
        ("allow-users", None, Some("strings"), "allow visitor users"),
        (
            "annotations",
            None,
            Some("stringToString"),
            "annotation key-value pairs (e.g., key1=value1,key2=value2) (default [])",
        ),
        (
            "bandwidth-limit",
            None,
            Some("string"),
            "bandwidth limit (e.g. 100KB or 1MB)",
        ),
        (
            "bandwidth-limit-mode",
            None,
            Some("string"),
            "bandwidth limit mode (default \"client\")",
        ),
        (
            "client-id",
            None,
            Some("string"),
            "unique identifier for this frpc instance",
        ),
        (
            "disable-log-color",
            None,
            None,
            "disable log color in console",
        ),
        (
            "dns-server",
            None,
            Some("string"),
            "specify dns server instead of using system default one",
        ),
        (
            "log-file",
            None,
            Some("string"),
            "console or file path (default \"console\")",
        ),
        (
            "log-level",
            None,
            Some("string"),
            "log level (default \"info\")",
        ),
        (
            "log-max-days",
            None,
            Some("int"),
            "log file reversed days (default 3)",
        ),
        (
            "metadatas",
            None,
            Some("stringToString"),
            "metadata key-value pairs (e.g., key1=value1,key2=value2) (default [])",
        ),
        (
            "protocol",
            Some('p'),
            Some("string"),
            "optional values are [tcp kcp quic websocket wss] (default \"tcp\")",
        ),
        ("tls-enable", None, None, "enable frpc tls (default true)"),
        ("user", Some('u'), Some("string"), "user"),
    ];

    #[test]
    fn the_go_only_proxy_rows_are_exactly_the_recorded_set() {
        let mut rendered: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (_, root, command, _, _) in SURFACES {
            if !surface_consults(root, command, "allow-users") {
                continue;
            }
            for line in surface_document(root, command).lines() {
                if let Some(long) = row_long_flag(line) {
                    rendered.insert(long.trim_start_matches("--").to_owned());
                }
            }
        }
        let unrendered: Vec<&str> = FRPC_PROXY_GO_FLAGS
            .iter()
            .map(|row| row.long)
            .filter(|long| !rendered.contains(*long))
            .collect();
        assert_eq!(
            unrendered,
            GO_ONLY_PROXY_ROWS.to_vec(),
            "the set of Go proxy rows frp-rs never renders changed: a row that became \
             implemented must be dropped from `GO_ONLY_PROXY_ROWS` (and its doc pins \
             regenerated), and a newly recorded Go row must appear in both"
        );
    }

    #[test]
    fn the_go_only_proxy_rows_carry_their_recorded_help_text() {
        let actual: Vec<(&str, Option<char>, Option<&str>, &str)> = FRPC_PROXY_GO_FLAGS
            .iter()
            .filter(|row| GO_ONLY_PROXY_ROWS.contains(&row.long))
            .map(|row| (row.long, row.short, row.varname, row.usage))
            .collect();
        assert_eq!(
            actual,
            GO_ONLY_PROXY_ROW_TEXT.to_vec(),
            "an unrendered Go proxy row's recorded help text changed: these cells are \
             never rendered, so `GO_ONLY_PROXY_ROW_TEXT` is their only witness — \
             re-transcribe the row from Go v0.71.0 instead of editing the witness"
        );
    }

    /// The `FRPC_PROXY_GO_FLAGS` rows every one of frp-rs's eight proxy commands
    /// renders, with Go's shorthand for each.
    ///
    /// `help_flag_tables` hands all eight surfaces the same 32-row union, and
    /// `go_flag_row` takes the first match, so a surface can pick up another
    /// surface's row — including its **shorthand**. That is how `.short('r')` on
    /// sudp's long-only `--remote-port` passed every other test in this module:
    /// the union lookup returned Go's tcp/udp row, whose `short` is `Some('r')`,
    /// and the loop in
    /// [`parser_shorthands_agree_with_go_where_the_parser_has_one`] only compares
    /// what that lookup returns. This per-surface pin compares each surface
    /// against Go's set for **that surface**, longs *and* shorthands, so it reds
    /// when a surface starts rendering a Go row it does not implement, drops one
    /// it does, or prints a shorthand that belongs to a different surface's row.
    /// One Go row as frp-rs renders it: the long name and the shorthand the
    /// surface actually prints (`None` when Go's own row carries no shorthand).
    type GoRowPin = (&'static str, Option<char>);

    const GO_PROXY_ROWS_UNIVERSAL: [GoRowPin; 8] = [
        ("local-ip", Some('i')),
        ("local-port", Some('l')),
        ("proxy-name", Some('n')),
        ("server-addr", Some('s')),
        ("server-port", Some('P')),
        ("token", Some('t')),
        ("uc", None),
        ("ue", None),
    ];

    /// Measured from the Go v0.71.0 binary: `frpc <surface> --help` renders the
    /// eight universal rows above on every proxy command, plus these. Go binds more
    /// than this on each surface (that is `GO_ONLY_PROXY_ROWS`); this is the part
    /// frp-rs implements. Sudp's `remote-port` is the one deliberate divergence:
    /// Go registers the row on tcp/udp only, and frp-rs keeps the long form on sudp
    /// as an extension, so the shorthand is `None` there where tcp/udp print `-r`.
    const GO_PROXY_ROWS_PER_SURFACE: [(&str, &[GoRowPin]); 8] = [
        ("frpc tcp", &[("remote-port", Some('r'))]),
        ("frpc udp", &[("remote-port", Some('r'))]),
        (
            "frpc http",
            &[
                ("custom-domain", Some('d')),
                ("host-header-rewrite", None),
                ("http-pwd", None),
                ("http-user", None),
                ("locations", None),
                ("sd", None),
            ],
        ),
        ("frpc https", &[("custom-domain", Some('d')), ("sd", None)]),
        ("frpc stcp", &[("sk", None), ("tls-server-name", None)]),
        ("frpc xtcp", &[("sk", None), ("tls-server-name", None)]),
        ("frpc sudp", &[("remote-port", None), ("sk", None)]),
        (
            "frpc tcpmux",
            &[("custom-domain", Some('d')), ("mux", None), ("sd", None)],
        ),
    ];

    #[test]
    fn every_proxy_surface_renders_exactly_the_go_rows_that_surface_implements() {
        let go_longs: std::collections::BTreeSet<&str> =
            FRPC_PROXY_GO_FLAGS.iter().map(|row| row.long).collect();
        for (label, extras) in GO_PROXY_ROWS_PER_SURFACE {
            let (_, root, command, _, _) = SURFACES
                .into_iter()
                .find(|(candidate, ..)| *candidate == label)
                .unwrap_or_else(|| panic!("`{label}` names no SURFACES row"));
            let mut expected: std::collections::BTreeMap<&str, Option<char>> =
                GO_PROXY_ROWS_UNIVERSAL.into_iter().collect();
            for (long, short) in extras {
                assert!(
                    go_longs.contains(long),
                    "`{label}`'s expected row `{long}` is not a Go proxy row at all"
                );
                assert!(
                    expected.insert(long, *short).is_none(),
                    "`{label}` records `{long}` twice"
                );
            }
            let rendered: Vec<(String, Option<char>)> =
                section_rows(&surface_document(root, command), "Flags:")
                    .into_iter()
                    .filter(|(_, long, _)| long != "help")
                    .map(|(head, long, _)| (long, printed_short(&head)))
                    .collect();
            let actual_longs: std::collections::BTreeSet<&str> = rendered
                .iter()
                .map(|(long, _)| long.as_str())
                .filter(|long| go_longs.contains(long))
                .collect();
            let expected_longs: std::collections::BTreeSet<&str> =
                expected.keys().copied().collect();
            assert_eq!(
                actual_longs, expected_longs,
                "`{label}` must render exactly Go's own rows for that surface: Go registers \
                 them all, and every one frp-rs implements must print (a row Go has on this \
                 surface but frp-rs does not implement, or vice versa, shows up here)"
            );
            for (long, short) in &rendered {
                if let Some(expected_short) = expected.get(long.as_str()) {
                    assert_eq!(
                        short, expected_short,
                        "`{label}` must print Go's own shorthand for `--{long}` on this \
                         surface ({expected_short:?}), not another surface row's shorthand"
                    );
                }
            }
        }
    }

    /// The two `SURFACES` columns no other assertion reads: the `label` (used only
    /// in failure messages) and the Go byte count (read only by
    /// `every_surface_is_pinned_by_its_byte_count`'s message). Both are derived, so
    /// they are re-derived here — a label must name its own root/command, and the
    /// two `verify` rows' Go column must be the byte length of the Go oracle
    /// constant that duplicates it.
    ///
    /// RESIDUE: the other thirteen Go byte counts were measured from the real Go
    /// binary in one session; `go-frp` is not a build dependency, so no in-tree
    /// artifact can re-measure them. They stay hand-transcribed documentation.
    #[test]
    fn surface_labels_and_the_verify_go_byte_counts_are_derived() {
        for (label, root, command, _, go) in SURFACES {
            let expected = match (root, command) {
                (RootCommand::Frps, None) => "frps".to_owned(),
                (RootCommand::Frps, Some(name)) => format!("frps {name}"),
                (RootCommand::Frpc, None) => "frpc".to_owned(),
                (RootCommand::Frpc, Some(name)) => format!("frpc {name}"),
            };
            assert_eq!(
                label,
                expected.as_str(),
                "the SURFACES label must name its own surface"
            );
            let oracle = match (root, command) {
                (RootCommand::Frps, Some("verify")) => Some(GO_FRPS_VERIFY),
                (RootCommand::Frpc, Some("verify")) => Some(GO_FRPC_VERIFY),
                _ => None,
            };
            if let Some(oracle) = oracle {
                assert_eq!(
                    go,
                    oracle.len(),
                    "{label}'s Go column must be the byte length of the Go oracle it duplicates"
                );
            }
            assert!(go > 0, "{label} must carry a measured Go byte count");
        }
        let mut labels: Vec<&str> = SURFACES.into_iter().map(|(label, ..)| label).collect();
        let count = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), count, "every SURFACES label must be unique");
    }
}
