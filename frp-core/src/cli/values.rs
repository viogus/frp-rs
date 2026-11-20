use std::ffi::OsString;

// `bpaf::*` re-exports the combinator functions but not this builder type, which
// [`go_bool_named`] returns.
use bpaf::parsers::NamedArg;
use bpaf::Parser;
use bpaf::*;

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
pub(crate) fn parse_go_bool(value: String) -> Result<bool, String> {
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
pub(crate) const STRICT_CONFIG_VALUE_HELP: &str = "Strict config parsing mode: true or false. The Go-faithful value spelling is --strict-config=<bool>";

/// Help for the bare `--strict-config` switch (Go-faithful) plus the extension
/// statement. See [`STRICT_CONFIG_VALUE_HELP`] for why these are `const`s.
pub(crate) const STRICT_CONFIG_SWITCH_HELP: &str = "Strict config parsing mode, unknown fields cause an error (default true). The Go-faithful spellings are this bare flag (=true) and --strict-config=<bool>; frp-rs additionally consumes a space-separated --strict-config <bool> as the value, which Go's pflag does not. A warning is printed when that extension is used";

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
pub(crate) fn strict_config_space_form_used(argv: &[OsString]) -> bool {
    argv.windows(2).any(|pair| {
        (pair[0] == "--strict-config" || pair[0] == "--strict_config")
            && pair[1].to_str().is_some_and(|value| {
                !value.starts_with('-') && parse_go_bool(value.to_string()).is_ok()
            })
    })
}

/// Print [`STRICT_CONFIG_SPACE_FORM_WARNING`] once if `argv` used the extension.
pub(crate) fn warn_if_strict_config_space_form_used(argv: &[OsString]) {
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
pub(crate) fn strict_config_parser() -> impl Parser<bool> {
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
pub(crate) fn go_bool_named(
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
pub(crate) fn go_bool_named_with_aliases(
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
