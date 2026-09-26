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
/// context `` (`TODO.md:1745`). This expands to the `=BOOL` spelling with Go's
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
    pub strict_config: bool,
    pub show_version: bool,
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
            subdomain_host: b.transport.subdomain_host,
            max_ports_per_client: b.transport.max_ports_per_client,
            tls_only: b.transport.tls_only,
        }
    }
}

// ─── Parser combinators ──────────────────────────────────────────────

fn svr_meta() -> impl Parser<SvrMeta> {
    let config = long("config")
        .short('c')
        .argument::<String>("FILE")
        .optional();
    let config_dir = long("config-dir")
        .long("config_dir")
        .argument::<String>("DIR")
        .optional();
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
    let allow_unsafe = long("allow-unsafe")
        .long("allow_unsafe")
        .argument::<String>("FEATURES")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .collect::<Vec<_>>()
        })
        .fallback(vec![]);
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

fn svr_log() -> impl Parser<SvrLog> {
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
        subdomain_host,
        max_ports_per_client,
        tls_only,
    })
}

fn frps_build() -> impl Parser<FrpsBuild> {
    let meta = svr_meta();
    let bind = svr_bind();
    let auth = svr_auth();
    let dash = svr_dashboard();
    let log = svr_log();
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

/// Raw parser for frps CLI. Returns the parser, doesn't run it.
pub fn frps_args() -> impl Parser<FrpsArgs> {
    frps_build().map(FrpsArgs::from)
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

/// Run an `OptionParser` over the argv [`cli_args`] produced and exit the way
/// `OptionParser::run` does (`err.print_message(self.info.max_width)`, then
/// `err.exit_code()`).
fn run_cli<T>(parser: bpaf::OptionParser<T>, name: Option<String>, rest: &[OsString]) -> T {
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
/// 2. [`hoist_leading_subcommand`] — cobra's command resolution, `frpc` only
///    (`has_subcommands`; Go's `frps` declares no subcommands, so there is
///    nothing to resolve and `frps` keeps the old behaviour exactly).
///
/// Both entry points call **this** function, which is what makes the shared
/// pass a single decision rather than two call sites that could drift:
/// [`parse_frps_args`] and [`parse_frpc_args`] differ only in which parser they
/// run over the result. Crate-private: the module's tests pin the chain (this
/// preparation, then the parser) through it, so they follow the same expression
/// the binaries use instead of calling a pass directly — see
/// `frps_takes_a_dash_shaped_config_value`.
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
fn prepared_cli_argv(rest: &[OsString], has_subcommands: bool) -> Vec<OsString> {
    let rewritten = rewrite_config_dash_values(rest);
    if has_subcommands {
        hoist_leading_subcommand(&rewritten)
    } else {
        rewritten
    }
}

/// The `frpc` subcommand names [`hoist_leading_subcommand`] recognises, in the
/// order [`frpc_parser`] composes them.
///
/// This is the **whole** implemented surface: Go's `frpc --help` also lists
/// `nathole` (not implemented in frp-rs) and the cobra built-ins `completion`
/// and `help`, so `frpc -c cfg.toml nathole` stays a leftover-token refusal
/// here. The set is not hand-trusted: `every_known_subcommand_name_has_a_parser_branch`
/// runs each name through `frpc_parser` and fails on a name with no command,
/// and `the_known_subcommand_list_is_exactly_the_parser_branches` fails when the
/// list and the parser disagree in the other direction too.
const FRPC_SUBCOMMANDS: [&str; 12] = [
    "tcp", "udp", "http", "https", "stcp", "xtcp", "sudp", "tcpmux", "verify", "reload", "status",
    "stop",
];

/// Whether `token` names one of the commands [`frpc_parser`] registers.
///
/// `s` is a whole argv token, never a prefix: cobra's `findNext`
/// (`cobra-1.8.0/command.go`) compares with `commandNameMatches`, i.e. string
/// equality (`EnablePrefixMatching` is off — frp does not set it), and frp-rs
/// does not implement prefix matching either.
fn is_known_subcommand(s: &str) -> bool {
    FRPC_SUBCOMMANDS.contains(&s)
}

/// Whether cobra's `stripFlags` would treat this token as a flag that swallows
/// the next argv token — `cobra-1.8.0/command.go`, verbatim in effect: a
/// `--long` without `=` whose flag carries no `NoOptDefVal`, or a
/// two-character short flag without `=`.
///
/// The exemption list is therefore **exactly the root flags that Go registers
/// with a pflag bool**, because a pflag bool sets `NoOptDefVal =
/// "true"` (`pflag-1.0.5/bool.go:56`, reached from `BoolVarP`). On `frpc`
/// those are two, both on `rootCmd`:
///
/// * `--version` / `-v` — `cmd/frpc/sub/root.go:52`;
/// * `--strict-config` / `--strict_config` — `cmd/frpc/sub/root.go:53`
///   (`BoolVarP(&strictConfigMode, "strict_config", "", true, …)`). Both
///   spellings are exempt because `rootCmd.SetGlobalNormalizationFunc(config.WordSepNormalizeFunc)`
///   makes pflag resolve `--strict-config` to the same flag.
///
/// Everything else consumes the next token: the three value-taking root flags
/// (`--config`/`-c`, `--config_dir`, `--allow-unsafe`, `cmd/frpc/sub/root.go:50-51,55`)
/// **and any flag cobra does not know**, because `hasNoOptDefVal` returns false
/// for a name that is not in the set — measured, `frpc -x status` and
/// `frpc --nodash status` are `unknown shorthand flag` / `unknown flag` on Go
/// (so the token after the unknown flag was never a candidate).
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
/// dials on Go, because `status` was not consumed.
fn consumes_value(s: &OsStr) -> bool {
    let Some(s) = s.to_str() else { return false };
    if s.contains('=') {
        return false;
    }
    match s.as_bytes() {
        [b'-', b'-', rest @ ..] if !rest.is_empty() => {
            rest != b"version" && rest != b"strict-config" && rest != b"strict_config"
        }
        [b'-', c] => *c != b'v',
        _ => false,
    }
}

/// Move `frpc`'s **leading** subcommand token to the front of the argv, the way
/// cobra resolves a command that follows leading root flags (`TODO.md:2566`).
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
/// Returns `argv` unchanged when there is nothing to hoist.
fn hoist_leading_subcommand(argv: &[OsString]) -> Vec<OsString> {
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
            i += if consumes_value(arg) { 2 } else { 1 };
            continue;
        }
        let Some(word) = arg.to_str() else {
            // Not valid UTF-8, so not a subcommand name; the first bare word has
            // been seen and cobra would not look further.
            return argv.to_vec();
        };
        if is_known_subcommand(word) && i > 0 {
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
pub fn parse_frps_args() -> FrpsArgs {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let (name, rest) = cli_args(&argv);
    // Go's pflag consumes a `-`-prefixed token as a config flag's value on
    // `frps` too; bpaf only refuses the tokens it classifies as flags (see
    // [`rewrite_config_dash_values`]). Shared with `frpc` through
    // [`prepared_cli_argv`] — measured on Go frps v0.71.0:
    // `-c --strict-config=false` and `-c -x` are
    // `open <token>: no such file or directory` there, and `-c --` is
    // `open --: no such file or directory`. `warn_if_strict_config_space_form_used`
    // keeps reading the original argv. `false`: Go's `frps` declares no
    // subcommands, so no hoist runs on this binary and its behaviour is
    // byte-identical to before.
    let parse_argv = prepared_cli_argv(&rest, false);
    let args = run_cli(
        frps_args()
            .to_options()
            .descr("frps is the server of frp-rs (https://github.com/fatedier/frp)"),
        name,
        &parse_argv,
    );
    // Only reached when the argv parsed: the failure path above exits the
    // process, so the warning can never fire for a refused argv, and the
    // detection never matches the `=`, bare or non-bool forms.
    warn_if_strict_config_space_form_used(&argv);
    if args.show_version {
        println!("frps {} (Rust)", crate::VERSION);
        std::process::exit(0);
    }
    args
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
}

#[derive(Debug, Clone)]
pub struct SudpArgs {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub proxy_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TcpmuxArgs {
    pub local_ip: String,
    pub local_port: u16,
    pub mux_port: u16,
    pub server_addr: String,
    pub server_port: u16,
    pub token: Option<String>,
    pub proxy_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifyArgs {
    pub config: String,
    /// Go frp v0.71.0: `strict_config` is a persistent rootCmd flag
    /// (cmd/frpc/sub/root.go), so `frpc verify` honors it too
    /// (cmd/frpc/sub/verify.go passes strictConfigMode to
    /// config.LoadClientConfig).
    pub strict_config: bool,
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
/// context` on the second occurrence, so every frpc parser that takes a config
/// path wraps the argument in [`Parser::last`] (bpaf's documented
/// contradicting-options combinator: run the inner parser as many times as it
/// succeeds and return the last value). `.last()` fails when the flag is
/// absent, exactly like the bare `argument` it replaces, so a required `-c`
/// stays required and an `.optional()`/`.fallback()` wrapper keeps its previous
/// meaning. The `frps` CLI is left alone: that is a separate surface, not part
/// of this item.
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

/// `--allow-unsafe`, as an ignored persistent root flag. Go registers it as a
/// pflag `strings` (comma-separated, repeatable), so repeats append; the value
/// is dropped here either way.
fn ignored_allow_unsafe() -> impl Parser<Vec<String>> {
    long("allow-unsafe")
        .long("allow_unsafe")
        .argument::<String>("FEATURES")
        .many()
}

/// `-v`/`--version`, as an ignored persistent root flag. Go registers it as a
/// persistent **rootCmd bool**, and only the root command's `RunE` prints the
/// version: measured on Go v0.71.0, `frpc tcp … --version` starts the proxy
/// exactly like the same argv without it. The value grammar is the shared
/// Go-bool one, so `--version=foo` is still the pflag value error.
fn ignored_version() -> impl Parser<bool> {
    go_bool_flag!("version", None, Some('v'), "Version of frpc").last()
}

/// The persistent root flags the four config-reading subcommands
/// (`verify`/`reload`/`status`/`stop`) did not declare: `-c` and
/// `--strict-config` are already fields of their own parsers.
fn ignored_admin_root_flags() -> impl Parser<()> {
    construct!(
        ignored_config_dir(),
        ignored_allow_unsafe(),
        ignored_version()
    )
    .map(|_| ())
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
    let allow_unsafe = long("allow-unsafe")
        .long("allow_unsafe")
        .argument::<String>("FEATURES")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .collect::<Vec<_>>()
        })
        .fallback(vec![]);
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
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let remote_port = long("remote-port")
        .long("remote_port")
        .argument::<u16>("PORT");
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    // Go registers this pair on `frpc tcp` under **different names**:
    // `--uc` ("use compression") and `--ue` ("use encryption"), both pflag
    // bools. frp-rs has always spelled them out; the names stay divergent (the
    // short pair is not implemented at all), but the value grammar is Go's —
    // measured, `frpc tcp --ue=false …` is accepted by Go and the proxy runs.
    let use_encryption = go_bool_flag!(
        "use-encryption",
        Some("use_encryption"),
        None,
        "Use encryption",
    );
    let use_compression = go_bool_flag!(
        "use-compression",
        Some("use_compression"),
        None,
        "Use compression",
    );
    let proxy_name = long("proxy-name")
        .long("proxy_name")
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
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let remote_port = long("remote-port")
        .long("remote_port")
        .argument::<u16>("PORT");
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .argument::<String>("NAME")
        .optional();
    let args = construct!(UdpArgs {
        local_ip,
        local_port,
        remote_port,
        server_addr,
        server_port,
        token,
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
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let custom_domains = long("custom-domains")
        .long("custom_domains")
        .argument::<String>("DOMAINS");
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let subdomain = long("subdomain").argument::<String>("SUB").optional();
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
        .argument::<String>("NAME")
        .optional();
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
    });
    single_proxy_cmd(args, FrpcCmd::Http)
        .to_options()
        .command("http")
        .help("Run frpc with a single http proxy")
}

fn https_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let custom_domains = long("custom-domains")
        .long("custom_domains")
        .argument::<String>("DOMAINS");
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let subdomain = long("subdomain").argument::<String>("SUB").optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .argument::<String>("NAME")
        .optional();
    let args = construct!(HttpsArgs {
        local_ip,
        local_port,
        custom_domains,
        server_addr,
        server_port,
        token,
        subdomain,
        proxy_name,
    });
    single_proxy_cmd(args, FrpcCmd::Https)
        .to_options()
        .command("https")
        .help("Run frpc with a single https proxy")
}

fn stcp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let sk = long("sk").argument::<String>("SECRET");
    let server_name = long("server-name")
        .long("server_name")
        .argument::<String>("NAME")
        .optional();
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let args = construct!(StcpArgs {
        sk,
        server_name,
        local_ip,
        local_port,
        server_addr,
        server_port,
        token,
    });
    single_proxy_cmd(args, FrpcCmd::Stcp)
        .to_options()
        .command("stcp")
        .help("Run frpc with a single stcp proxy")
}

fn xtcp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let sk = long("sk").argument::<String>("SECRET");
    let server_name = long("server-name")
        .long("server_name")
        .argument::<String>("NAME")
        .optional();
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let args = construct!(XtcpArgs {
        sk,
        server_name,
        local_ip,
        local_port,
        server_addr,
        server_port,
        token,
    });
    single_proxy_cmd(args, FrpcCmd::Xtcp)
        .to_options()
        .command("xtcp")
        .help("Run frpc with a single xtcp proxy")
}

fn sudp_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let remote_port = long("remote-port")
        .long("remote_port")
        .argument::<u16>("PORT");
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .argument::<String>("NAME")
        .optional();
    let args = construct!(SudpArgs {
        local_ip,
        local_port,
        remote_port,
        server_addr,
        server_port,
        token,
        proxy_name,
    });
    single_proxy_cmd(args, FrpcCmd::Sudp)
        .to_options()
        .command("sudp")
        .help("Run frpc with a single sudp proxy")
}

fn tcpmux_cmd() -> impl Parser<FrpcCmd> {
    let local_ip = long("local-ip")
        .long("local_ip")
        .argument::<String>("IP")
        .fallback("127.0.0.1".into());
    let local_port = long("local-port")
        .long("local_port")
        .argument::<u16>("PORT");
    let mux_port = long("mux-port").long("mux_port").argument::<u16>("PORT");
    let server_addr = long("server-addr")
        .long("server_addr")
        .argument::<String>("HOST")
        .fallback("127.0.0.1".into());
    let server_port = long("server-port")
        .long("server_port")
        .argument::<u16>("PORT")
        .fallback(7000);
    let token = long("token")
        .short('t')
        .argument::<String>("TOKEN")
        .optional();
    let proxy_name = long("proxy-name")
        .long("proxy_name")
        .argument::<String>("NAME")
        .optional();
    let args = construct!(TcpmuxArgs {
        local_ip,
        local_port,
        mux_port,
        server_addr,
        server_port,
        token,
        proxy_name,
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
    let args = construct!(VerifyArgs {
        config,
        strict_config
    });
    construct!(args, ignored_admin_root_flags())
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
    let parse_argv = prepared_cli_argv(&rest, true);
    let args = run_cli(
        frpc_parser()
            .to_options()
            .descr("frpc is the client of frp-rs (https://github.com/fatedier/frp)"),
        name,
        &parse_argv,
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
    pub fn override_server_config(&self, cfg: &mut crate::config::ServerConfig) {
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

        // Log
        if let Some(ref v) = self.log_file {
            cfg.log.file = v.clone();
        }
        if let Some(ref v) = self.log_level {
            cfg.log.level = v.clone();
        }
        if let Some(v) = self.log_max_days {
            cfg.log.max_days = v;
        }
        if let Some(ref v) = self.log_format {
            cfg.log.format = v.clone();
        }

        // Transport / ports
        #[cfg(feature = "kcp")]
        if let Some(v) = self.kcp_bind_port {
            cfg.kcp_bind_port = v;
        }
        #[cfg(feature = "quic")]
        if let Some(v) = self.quic_bind_port {
            cfg.quic_bind_port = v;
        }
        if let Some(v) = self.vhost_http_port {
            cfg.vhost_http_port = v;
        }
        if let Some(v) = self.vhost_https_port {
            cfg.vhost_https_port = v;
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
            ..Default::default()
        }
    }
}

impl StcpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self
                .server_name
                .clone()
                .unwrap_or_else(|| "stcp-proxy".into()),
            proxy_type: "stcp".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            sk: self.sk.clone(),
            ..Default::default()
        }
    }
}

impl XtcpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            name: self
                .server_name
                .clone()
                .unwrap_or_else(|| "xtcp-proxy".into()),
            proxy_type: "xtcp".into(),
            local_ip: self.local_ip.clone(),
            local_port: self.local_port,
            sk: self.sk.clone(),
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
            remote_port: self.mux_port,
            multiplexer: "httpconnect".into(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_frps(args: &[&str]) -> Result<FrpsArgs, bpaf::ParseFailure> {
        frps_args().to_options().run_inner(args)
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

    /// `frpc tcp` — the only surface that carries the `--ue`/`--uc` pair on Go
    /// and `--use-encryption`/`--use-compression` here.
    fn parse_frpc_tcp(args: &[&str]) -> Result<TcpArgs, bpaf::ParseFailure> {
        match frpc_parser().to_options().run_inner(args)? {
            FrpcCmd::Tcp(a) => Ok(a),
            other => panic!("expected tcp command, got {other:?}"),
        }
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

    /// Every parser that accepts `--strict-config`, as
    /// `(label, argv)` — `frps`, then `frpc`'s `run`/`verify`/`reload`/
    /// `status`/`stop`. `-c x.toml` is present throughout because `verify`
    /// requires it; the other five fall back and never read the file (these
    /// helpers only run the bpaf parser).
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
        // The done-when for `TODO.md:1613` requires the divergence stated in
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
    // 1 here (`TODO.md:1745`). The rows below are the parser half; the
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
        (
            "frpc tcp --use-encryption",
            "--use-encryption",
            Some("--use_encryption"),
        ),
        (
            "frpc tcp --use-compression",
            "--use-compression",
            Some("--use_compression"),
        ),
        ("frpc status --json", "--json", None),
    ];

    /// Parse the flag under test on its own surface: the required positional
    /// arguments of `frpc tcp`/`frpc status` are supplied, and the flag argv is
    /// appended.
    fn parse_site(site: &str, flag_argv: &[&str]) -> Result<bool, bpaf::ParseFailure> {
        let base: &[&str] = match site {
            "frpc tcp --use-encryption" | "frpc tcp --use-compression" => {
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
            "frpc tcp --use-encryption" => parse_frpc_tcp(&argv).map(|a| a.use_encryption),
            "frpc tcp --use-compression" => parse_frpc_tcp(&argv).map(|a| a.use_compression),
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
            ("frpc tcp", "--use-encryption", "Use encryption", "go-bool"),
            (
                "frpc tcp",
                "--use-compression",
                "Use compression",
                "go-bool",
            ),
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
            .run_inner(&prepared_cli_argv(&argv, false)[..])
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
                .run_inner(&prepared_cli_argv(&argv, false)[..])
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
            .run_inner(&prepared_cli_argv(&argv, false)[..])
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
}

#[cfg(test)]
mod hoist_tests {
    use super::*;

    fn hoist(args: &[&str]) -> Vec<String> {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        hoist_leading_subcommand(&argv)
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    fn prepared(args: &[&str]) -> Vec<String> {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        prepared_cli_argv(&argv, true)
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    fn run_frpc(args: &[&str]) -> Result<FrpcCmd, bpaf::ParseFailure> {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        let prepared = prepared_cli_argv(&argv, true);
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
                consumes_value(OsStr::new(takes)),
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
                !consumes_value(OsStr::new(keeps)),
                "{keeps} must not swallow the next token"
            );
        }
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
        let prepared =
            prepared_cli_argv(&[OsString::from("--help"), OsString::from("status")], true);
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
            let prepared = prepared_cli_argv(&[OsString::from(name)], true);
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
}
