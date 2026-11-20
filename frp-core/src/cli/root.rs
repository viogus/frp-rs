use std::ffi::OsStr;
use std::ffi::OsString;

use bpaf::Parser;
use bpaf::*;

use super::*;

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
pub(crate) fn run_cli<T>(
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
pub(crate) fn prepared_cli_argv(rest: &[OsString], root: RootCommand) -> Vec<OsString> {
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
pub(crate) enum RootCommand {
    Frps,
    Frpc,
}

impl RootCommand {
    /// The child command names cobra's `Find` can resolve on this root — the
    /// **whole implemented** surface, not Go's full list (cobra's `completion`
    /// and `help` are not implemented on either binary).
    pub(crate) fn subcommands(self) -> &'static [&'static str] {
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
    pub(crate) fn bool_root_flags(self) -> &'static [&'static str] {
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
pub(crate) const FRPC_SUBCOMMANDS: [&str; 12] = [
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
pub(crate) const FRPS_SUBCOMMANDS: [&str; 1] = ["verify"];

/// The pflag **bool** long flags of Go's `frps` root command, normalized to `_`.
/// See [`RootCommand::bool_root_flags`] for the source lines and the probes.
pub(crate) const FRPS_BOOL_ROOT_FLAGS: [&str; 5] = [
    "version",
    "strict_config",
    "enable_prometheus",
    "disable_log_color",
    "tls_only",
];

/// The pflag **bool** long flags of Go's `frpc` root command, normalized to `_`.
/// See [`RootCommand::bool_root_flags`].
pub(crate) const FRPC_BOOL_ROOT_FLAGS: [&str; 2] = ["version", "strict_config"];

/// Whether `token` names one of the commands `root` registers.
///
/// `s` is a whole argv token, never a prefix: cobra's `findNext`
/// (`cobra-1.8.0/command.go`) compares with `commandNameMatches`, i.e. string
/// equality (`EnablePrefixMatching` is off — frp does not set it), and frp-rs
/// does not implement prefix matching either.
pub(crate) fn is_known_subcommand(s: &str, root: RootCommand) -> bool {
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
pub(crate) fn consumes_value(s: &OsStr, root: RootCommand) -> bool {
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
pub(crate) fn hoist_leading_subcommand(argv: &[OsString], root: RootCommand) -> Vec<OsString> {
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
pub(crate) fn config_arg() -> impl Parser<String> {
    long("config").short('c').argument::<String>("FILE").last()
}

// ─── The persistent rootCmd flags every subcommand parses ────────────
/// `--config-dir`, as an ignored persistent root flag. Same spellings as the
/// run-mode flag (hyphen plus the frp-rs underscore alias) and Go's pflag
/// semantics: last-wins on repetition.
pub(crate) fn ignored_config_dir() -> impl Parser<Option<String>> {
    long("config-dir")
        .long("config_dir")
        .argument::<String>("DIR")
        .last()
        .optional()
}
