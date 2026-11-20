use std::ffi::OsStr;
use std::ffi::OsString;

use super::*;

/// The output width bpaf's own `OptionParser::run` passes to
/// `ParseFailure::print_message` — `OptionParserInfo::default().max_width`
/// (`bpaf-0.9.27/src/info.rs:46`), and no parser here calls `.max_width()`.
/// Spelled out because the two entry points below build bpaf's `Args` by hand
/// (to apply [`expand_bool_short_value_form`]) and therefore cannot use `run()`.
pub(crate) const CLI_OUTPUT_WIDTH: usize = 100;

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
pub(crate) fn expand_bool_short_value_form(argv: Vec<OsString>) -> Vec<OsString> {
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
///   (`frp-core/src/cli/root.rs`, `config_arg`);
/// * `-p` and `-t` are `frps`'s own on its **root** — `bind_port`
///   (`pkg/config/flags.go:231`) and `token` (`:247`) — and `-t` is also
///   `frpc`'s `token` on its proxy and visitor subcommands (`:171`);
/// * `-L` is **frpc's run path only** — frp-rs's alias for `--log-level`
///   (`frp-core/src/cli/frpc.rs`, the `run_mode` parser). It is *not* a Go shorthand
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
/// (frp-rs's own alias for `--log-level`, `frp-core/src/cli/frpc.rs` `run_mode`) are
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
pub(crate) const VALUE_TAKING_SHORTS_FRPC_ROOT: [char; 4] = ['c', 'p', 't', 'L'];

/// `frps`'s root takes `-c`, `-p` (`bind_port`, `pkg/config/flags.go:231`) and
/// `-t` (`token`, `:247`) and **no `-L`**: Go registers `log_level` with an empty
/// shorthand (`:244`) and frp-rs's `svr_log` gives `log-level` no short either.
/// The two roots therefore need **separate** sets — sharing frpc's made
/// `frps -hL` print a `flag needs an argument: 'L' in -L` for a short frps does
/// not register, which is exactly the fabricated line this constant exists to
/// avoid on the subcommand set.
pub(crate) const VALUE_TAKING_SHORTS_FRPS_ROOT: [char; 3] = ['c', 'p', 't'];

/// Every **subcommand** of both binaries: `-c` is persistent on both, and `-p` /
/// `-t` cover the `frps verify` and `frpc` proxy surfaces. `-L` is absent here on
/// both binaries, so `frpc status -hL`, `frpc tcp -hL` and `frps verify -hL` get
/// bpaf's own reading rather than a missing-argument line for a short those
/// parsers do not have.
pub(crate) const VALUE_TAKING_SHORTS_SUBCOMMAND: [char; 3] = ['c', 'p', 't'];

/// The root set for a binary: the two roots are **not** the same list.
pub(crate) fn value_taking_root_shorts(root: RootCommand) -> &'static [char] {
    match root {
        RootCommand::Frpc => &VALUE_TAKING_SHORTS_FRPC_ROOT,
        RootCommand::Frps => &VALUE_TAKING_SHORTS_FRPS_ROOT,
    }
}

/// Which value-taking short set a pass uses: the root command's (a bare `frpc`
/// invocation, which is the run path and *does* have `-L`, or `frps`'s root) or a
/// subcommand's (which does not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShortFlagContext {
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
    pub(crate) fn of(argv: &[OsString], root: RootCommand) -> Self {
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
pub(crate) fn value_taking_short_name(token: &OsStr, context: ShortFlagContext) -> Option<char> {
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
pub(crate) fn help_cluster_naming_a_value_short(
    token: &OsStr,
    context: ShortFlagContext,
) -> Option<char> {
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
pub(crate) fn attach_flag_shaped_values(argv: Vec<OsString>, root: RootCommand) -> Vec<OsString> {
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
pub(crate) const VALUE_TAKING_LONG_FLAGS: &[&str] = &[
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
pub(crate) fn claims_the_next_token(
    token: &OsStr,
    context: ShortFlagContext,
    root: RootCommand,
) -> bool {
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
pub(crate) struct ArgvWalk {
    /// Indices pflag hands to a flag as its **value**, so no later pass may read
    /// them as flags: `frpc -hc --help=false status` is `-c`'s value, not a help
    /// request, and `frpc -hc -hc` gives the second cluster to the first's `-c`.
    pub(crate) consumed: Vec<bool>,
    /// `Some(c)` when the walk ended needing a value for short `c` — the one
    /// shape that reaches a parse error.
    pub(crate) needs_argument: Option<char>,
    /// Whether the token that produced [`Self::needs_argument`] was a `-h<short>`
    /// **cluster** (as opposed to a bare `-c`). Only the cluster shape is this
    /// pass's business: a bare `-c` with nothing after it is already a bpaf
    /// error on the right stream with rc 1 (`` `-c` requires an argument `FILE` ``,
    /// measured 40 B on stderr), while `-hc` reaches bpaf's help and exits 0.
    pub(crate) needs_argument_is_help_cluster: bool,
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
pub(crate) fn walk_argv(
    argv: &[OsString],
    context: ShortFlagContext,
    root: RootCommand,
) -> ArgvWalk {
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
pub(crate) fn reject_pflag_shorthand_cluster_that_needs_a_value(
    argv: &[OsString],
    root: RootCommand,
) {
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
pub(crate) fn expand_help_bool_value_form(argv: Vec<OsString>, root: RootCommand) -> Vec<OsString> {
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
pub(crate) fn cli_args(argv: &[OsString]) -> (Option<String>, Vec<OsString>) {
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
