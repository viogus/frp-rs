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
    /// **R6(b) (`TODO.md:11218`): "accept-and-ignore matches Go" is bounded.**
    /// The flag surface is Go's (the full `int64` accepted above), but the value
    /// that reaches the vhost handler is clamped: `<= 0` floors at 60 s and
    /// anything above 24 h is capped, where Go has no comparable cap. So the
    /// bound is "values `<= 0` or below the cap behave like Go"; a positive value
    /// above 24 h is accepted here and then silently shortened. Measured by the
    /// unit pin `frp-server/src/vhost/tests.rs:252` (`test_clamp_vhost_timeout`):
    /// `0 → 60`, `-1 → 60`, `86400 → 86400`, `86401 → 86400`, `i64::MAX →
    /// 86400`; the cap is `frp-server/src/vhost.rs:128`
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
/// commands" — the premise the old comment in this doc recorded and
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
/// **R6(a) (`TODO.md:11218`): this lane does not read the loaded config's `[log]`
/// section.** `init_logging(&cli, None)` (`frps/src/main.rs:657`) runs before
/// `collect_config_files` (`frps/src/main.rs:673`), so the effective log level
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
///   (`frp-core/src/cli/mod.rs`, `config_arg`);
/// * `-p` and `-t` are `frps`'s own on its **root** — `bind_port`
///   (`pkg/config/flags.go:231`) and `token` (`:247`) — and `-t` is also
///   `frpc`'s `token` on its proxy and visitor subcommands (`:171`);
/// * `-L` is **frpc's run path only** — frp-rs's alias for `--log-level`
///   (`frp-core/src/cli/mod.rs`, the `run_mode` parser). It is *not* a Go shorthand
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
/// (frp-rs's own alias for `--log-level`, `frp-core/src/cli/mod.rs` `run_mode`) are
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
    // (`frp-server/src/ssh_gateway/args.rs:692`), and `ProxyConfig::multiplexer`
    // (frp-core/src/config/client.rs:741) is where it lands. A literal
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
    /// **R2 (`TODO.md:11174`): this implicit-`./frps.toml` lane is an frp-rs
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
mod help_doc_tests;
#[cfg(test)]
mod hoist_tests;
#[cfg(test)]
mod tests;
