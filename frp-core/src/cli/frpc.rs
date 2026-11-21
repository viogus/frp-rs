use std::ffi::OsString;
use std::time::Duration;

use bpaf::Parser;
use bpaf::*;

use super::*;

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

/// `frpc_root_flag_specs`' struct arm: the rows become [`FrpcRunArgs`].
///
/// The arm emits the struct, not the `construct!` that fills it. Writing that
/// call *inside* this macro cannot work: it fills each field from a local of
/// the same name in `run_mode`, and an identifier written in a macro body — or
/// handed through one, as the rows are — carries that expansion's syntax
/// context, so it fails with `error[E0425]: cannot find value` plus the hint
/// "an identifier with the same name exists, but is not accessible due to
/// macro hygiene".
///
/// It can be generated *indirectly*: a macro-emitted binder
/// `fn frpc_root_run_parser($($field: impl Parser<$ty>),*) -> impl
/// Parser<FrpcRunArgs>` whose body is `construct!(FrpcRunArgs { $($field),* })`
/// compiles and was measured to produce identical `--help` output. It is not
/// used, because passing the parsers positionally drops the field-name↔parser
/// correspondence: swapping two same-typed arguments (`log_file` and
/// `log_level`, say) then compiles and passes every test, while the name-based
/// call below rejects that swap by construction.
///
/// So the call site stays written out — and is checked rather than free: every
/// field this arm emits is a field that literal must fill, so a row added to
/// the list breaks the build with `error[E0063]` until the site names it too.
///
/// Its pattern mirrors `frpc_root_flag_tables` in `flag_tables.rs`: both open
/// the same list, so a change to the row shape has to change both.
macro_rules! frpc_root_args_struct {
    (
        $( ( $(#[$doc:meta])* $field:ident : $ty:ty $(, go ( long: $glong:literal, short: $gshort:expr, varname: $gvarname:expr, usage: $gusage:literal ) )? $(, ext ( long: $elong:literal, short: $eshort:expr, varname: $evarname:expr, usage: $eusage:literal ) )? $(,)? ) ),* $(,)?
    ) => {
        #[derive(Debug, Clone)]
        pub struct FrpcRunArgs {
            $( $(#[$doc])* pub $field: $ty, )*
        }
    };
}

frpc_root_flag_specs!(frpc_root_args_struct);

/// `proxy_flag_specs`' struct arm: the rows become the eight single-proxy
/// argument structs.
///
/// A struct has to be generated **whole** — a macro cannot expand to struct
/// fields (`struct S { fields!() }` is `error: unexpected token: '!'`) — so one
/// expansion emits both halves, the common rows first and the command's own rows
/// after. That is what the `common $common:tt` carrier is for:
/// `proxy_args_structs` takes the `common { … }` block as a single token tree
/// and hands it to `proxy_args_struct` for each command, whose pattern
/// destructures it beside that command's rows.
///
/// Nesting the two row repetitions in one output repetition instead — the
/// obvious first draft — does not compile, because the outer repetition drives
/// both: the error is a repetition mismatch naming the common rows' meta and the
/// command rows' meta, and its two counts are the two lists' lengths. Reproduced
/// standalone with three common rows and two command rows, where the compiler
/// said: meta-variable `cf` repeats 3 times, but `f` repeats 2 times.
///
/// The emitted field order is common-then-own, not the order the hand-written
/// structs used (stcp/xtcp declared `sk` and `server_name` first). Nothing reads
/// it: none of these structs derives `Serialize`/`Deserialize`, every
/// `construct!` fills by field name, the help renderer sorts by long
/// (`frp-core/src/cli/help_render.rs`), and no test asserts `Debug` output.
///
/// This arm ignores the group's variant, function name and command name; the
/// parser arm spends them.
macro_rules! proxy_args_struct {
    (
        { $( ( $(#[$cdoc:meta])* $cfield:ident : $cty:ty, $($crest:tt)* ) ),* $(,)? }
        | $sname:ident | $variant:ident | $fn:ident | $command:literal
        | $( ( $(#[$fdoc:meta])* $field:ident : $ty:ty, $($rest:tt)* ) ),* $(,)?
    ) => {
        #[derive(Debug, Clone)]
        pub struct $sname {
            $( $(#[$cdoc])* pub $cfield: $cty, )*
            $( $(#[$fdoc])* pub $field: $ty, )*
        }
    };
}

/// `proxy_flag_specs`' struct arm, applied to every command group.
macro_rules! proxy_args_structs {
    (
        common $common:tt
        $( $sname:ident as $variant:ident, $fn:ident, $command:literal { $( $row:tt )* } )+
    ) => {
        $( proxy_args_struct! { $common | $sname | $variant | $fn | $command | $( $row )* } )+
    };
}

proxy_flag_specs!(proxy_args_structs);

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

/// `frpc_admin_flag_specs`' struct arm: the five rows become the admin fields of
/// all three admin argument structs — `ReloadArgs`, `StatusArgs`, `StopArgs`,
/// which is why a row added to the list reaches every one of them.
///
/// What stays hand-written is each struct's non-admin tail (`config`,
/// `strict_config`, and `--json` on `StatusArgs`), written **before** the
/// generated block so the field order is exactly the one the hand-written
/// structs had. The tail could in principle stay at the call site and be
/// declared last — `macro_rules! m { ($($tail:tt)*) => { struct S { pub a: u8, $($tail)* } } }`
/// compiles — but then it would have to be threaded through both expanders as
/// a second `tt` parameter that only `ReloadArgs` uses, so it is written inside
/// the body instead. Declaration order is review-only (nothing tests it), but
/// it is observable: it is what `Debug` prints, and what the `git diff` of the
/// three structs against the pre-refactor file is read for.
///
/// The `construct!`s in `reload_cmd`, `status_cmd` and `stop_cmd` are
/// untouched, for the reason `frpc_root_args_struct` records: an identifier in a
/// macro body cannot name a call-site local, so the sites that fill these
/// structs stay written out — and are the compile check that every generated
/// field is filled.
///
/// Its pattern mirrors `frpc_admin_flag_tables` in `flag_tables.rs`: both open the
/// same list, so a change to the row shape has to change both.
macro_rules! frpc_admin_args_structs {
    (
        $( ( $(#[$doc:meta])* $field:ident : $ty:ty $(, go ( long: $glong:literal, short: $gshort:expr, varname: $gvarname:expr, usage: $gusage:literal ) )? $(, ext ( long: $elong:literal, short: $eshort:expr, varname: $evarname:expr, usage: $eusage:literal ) )? $(,)? ) ),* $(,)?
    ) => {
        #[derive(Debug, Clone)]
        pub struct ReloadArgs {
            pub config: Option<String>,
            pub strict_config: bool,
            $( $(#[$doc])* pub $field: $ty, )*
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
            $( $(#[$doc])* pub $field: $ty, )*
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
            $( $(#[$doc])* pub $field: $ty, )*
        }
    };
}

frpc_admin_flag_specs!(frpc_admin_args_structs);

/// Attach [`ignored_proxy_root_flags`] to one single-proxy command's own
/// argument parser and map the pair down to the command's `FrpcCmd` variant.
pub(crate) fn single_proxy_cmd<T, P, F>(args: P, f: F) -> impl Parser<FrpcCmd>
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
pub(crate) fn rewrite_config_dash_values(argv: &[OsString]) -> Vec<OsString> {
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

pub(crate) fn run_mode() -> impl Parser<FrpcRunArgs> {
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

// ─── The eight single-proxy parsers, generated from `proxy_flag_specs` ───

/// One row's flag as a parser expression — the four kinds [`proxy_flag_specs`]
/// declares.
///
/// Each rule expands to an **expression**, and the `let` that names it is
/// written by `proxy_cmd_parser`, not here: the row's tokens carry the row
/// list's syntax context, so a binder emitted inside this macro would not be the
/// binding its own initialiser produces. That is the same hygiene rule that
/// keeps the `construct!` call in `proxy_cmd_parser`.
///
/// Aliases are chained *after* the primary `long`, which is the only one bpaf
/// renders. An alias parses and never shows, which is what keeps the `--help`
/// pins measuring exactly one spelling per row.
macro_rules! proxy_field_parser {
    ( str, $long:literal, [ $( $alias:literal ),* ], $short:expr, $metavar:literal ) => {
        named_with_aliases($long, &[ $( $alias ),* ], $short).argument::<String>($metavar)
    };
    ( str, $long:literal, [ $( $alias:literal ),* ], $short:expr, $metavar:literal, fallback: $fallback:expr ) => {
        named_with_aliases($long, &[ $( $alias ),* ], $short)
            .argument::<String>($metavar)
            .fallback($fallback.into())
    };
    ( u16, $long:literal, [ $( $alias:literal ),* ], $short:expr, $metavar:literal ) => {
        named_with_aliases($long, &[ $( $alias ),* ], $short).argument::<u16>($metavar)
    };
    ( u16, $long:literal, [ $( $alias:literal ),* ], $short:expr, $metavar:literal, fallback: $fallback:expr ) => {
        named_with_aliases($long, &[ $( $alias ),* ], $short)
            .argument::<u16>($metavar)
            .fallback($fallback)
    };
    ( opt_str, $long:literal, [ $( $alias:literal ),* ], $short:expr, $metavar:literal ) => {
        named_with_aliases($long, &[ $( $alias ),* ], $short)
            .argument::<String>($metavar)
            .optional()
    };
    ( go_bool, $long:literal, [ $( $alias:literal ),* ], $meaning:literal ) => {
        go_bool_flag_with_aliases!($long, &[ $( $alias ),* ], None, $meaning)
    };
}

/// `proxy_flag_specs`' parser arm, one command at a time.
///
/// Every `let` and the `construct!` that consumes them come out of this one
/// expansion, which is what makes the construct site legal: a macro cannot name
/// a local at its call site (the constraint recorded on `frpc_root_args_struct`),
/// but it can emit the local itself and name that. [`proxy_args_struct`]
/// generates the struct the same way from the same rows, so the names in this
/// call are the names in that struct by construction rather than by review.
///
/// The command's help text comes from `FRPC_COMMAND_SHORTS`, the table the root
/// document renders — one statement of the text instead of a fourth copy that
/// only a byte pin would catch drifting.
macro_rules! proxy_cmd_parser {
    (
        { $( ( $(#[$cdoc:meta])* $cfield:ident : $cty:ty, $($crest:tt)* ) ),* $(,)? }
        | $sname:ident | $variant:ident | $fn:ident | $command:literal
        | $( ( $(#[$fdoc:meta])* $field:ident : $ty:ty, $($rest:tt)* ) ),* $(,)?
    ) => {
        pub(crate) fn $fn() -> impl Parser<FrpcCmd> {
            $( let $cfield = proxy_field_parser!($($crest)*); )*
            $( let $field = proxy_field_parser!($($rest)*); )*
            let args = construct!($sname { $( $cfield, )* $( $field, )* });
            single_proxy_cmd(args, FrpcCmd::$variant)
                .to_options()
                .command($command)
                .help(command_short(RootCommand::Frpc, $command))
        }
    };
}

/// `proxy_flag_specs`' parser arm, applied to every command group.
macro_rules! proxy_cmd_parsers {
    (
        common $common:tt
        $( $sname:ident as $variant:ident, $fn:ident, $command:literal { $( $row:tt )* } )+
    ) => {
        $( proxy_cmd_parser! { $common | $sname | $variant | $fn | $command | $( $row )* } )+
    };
}

proxy_flag_specs!(proxy_cmd_parsers);

pub(crate) fn verify_cmd() -> impl Parser<FrpcCmd> {
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

pub(crate) fn reload_cmd() -> impl Parser<FrpcCmd> {
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

pub(crate) fn status_cmd() -> impl Parser<FrpcCmd> {
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
pub(crate) fn stop_cmd() -> impl Parser<FrpcCmd> {
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
pub(crate) fn frpc_parser() -> impl Parser<FrpcCmd> {
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
//
// Each `to_proxy_config` opens with an **exhaustive** destructure of its own
// argument struct. That is the only thing holding the row list to the config
// it feeds: the struct is generated from `proxy_flag_specs`, so a row added
// there without a destination here fails to compile (`E0027`, "pattern does
// not mention field `…`") instead of parsing into a field nothing reads.
// The compiler asks for a destination, it does not prove one is right: binding
// a field to `_` compiles, so the guarantee is "no field is forgotten", not
// "no field is dropped". The three client-side fields every command carries —
// `server_addr`, `server_port`, `token` — are discarded *here* precisely
// because they are consumed at the call site: `run_single_proxy` in
// `frpc/src/main.rs` hands them to `build_single_proxy_config`, which writes
// them into `ClientConfig`.
impl TcpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let Self {
            local_ip,
            local_port,
            remote_port,
            proxy_name,
            server_addr: _,
            server_port: _,
            token: _,
            use_encryption,
            use_compression,
        } = self;
        crate::config::ProxyConfig {
            name: proxy_name
                .clone()
                .unwrap_or_else(|| format!("tcp-{}->{}", local_port, remote_port)),
            proxy_type: "tcp".into(),
            local_ip: local_ip.clone(),
            local_port: *local_port,
            remote_port: *remote_port,
            use_encryption: *use_encryption,
            use_compression: *use_compression,
            ..Default::default()
        }
    }
}

impl UdpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let Self {
            local_ip,
            local_port,
            remote_port,
            proxy_name,
            server_addr: _,
            server_port: _,
            token: _,
            use_encryption,
            use_compression,
        } = self;
        crate::config::ProxyConfig {
            name: proxy_name
                .clone()
                .unwrap_or_else(|| format!("udp-{}->{}", local_port, remote_port)),
            proxy_type: "udp".into(),
            local_ip: local_ip.clone(),
            local_port: *local_port,
            remote_port: *remote_port,
            use_encryption: *use_encryption,
            use_compression: *use_compression,
            ..Default::default()
        }
    }
}

impl HttpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let Self {
            local_ip,
            local_port,
            custom_domains,
            subdomain,
            locations,
            http_user,
            http_pwd,
            host_header_rewrite,
            proxy_name,
            server_addr: _,
            server_port: _,
            token: _,
            use_encryption,
            use_compression,
        } = self;
        let domains: Vec<String> = custom_domains
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        crate::config::ProxyConfig {
            name: proxy_name
                .clone()
                .unwrap_or_else(|| format!("http-{}", local_port)),
            proxy_type: "http".into(),
            local_ip: local_ip.clone(),
            local_port: *local_port,
            custom_domains: domains,
            subdomain: subdomain.clone().unwrap_or_default(),
            locations: locations
                .clone()
                .map(|l| l.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
            http_user: http_user.clone().unwrap_or_default(),
            http_pwd: http_pwd.clone().unwrap_or_default(),
            host_header_rewrite: host_header_rewrite.clone().unwrap_or_default(),
            use_encryption: *use_encryption,
            use_compression: *use_compression,
            ..Default::default()
        }
    }
}

impl HttpsArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let Self {
            local_ip,
            local_port,
            custom_domains,
            subdomain,
            proxy_name,
            server_addr: _,
            server_port: _,
            token: _,
            use_encryption,
            use_compression,
        } = self;
        let domains: Vec<String> = custom_domains
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        crate::config::ProxyConfig {
            name: proxy_name
                .clone()
                .unwrap_or_else(|| format!("https-{}", local_port)),
            proxy_type: "https".into(),
            local_ip: local_ip.clone(),
            local_port: *local_port,
            custom_domains: domains,
            subdomain: subdomain.clone().unwrap_or_default(),
            use_encryption: *use_encryption,
            use_compression: *use_compression,
            ..Default::default()
        }
    }
}

impl StcpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let Self {
            local_ip,
            local_port,
            proxy_name,
            server_name,
            sk,
            server_addr: _,
            server_port: _,
            token: _,
            use_encryption,
            use_compression,
        } = self;
        crate::config::ProxyConfig {
            name: proxy_name
                .clone()
                .or_else(|| server_name.clone())
                .unwrap_or_else(|| "stcp-proxy".into()),
            proxy_type: "stcp".into(),
            local_ip: local_ip.clone(),
            local_port: *local_port,
            sk: sk.clone(),
            use_encryption: *use_encryption,
            use_compression: *use_compression,
            ..Default::default()
        }
    }
}

impl XtcpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let Self {
            local_ip,
            local_port,
            proxy_name,
            server_name,
            sk,
            server_addr: _,
            server_port: _,
            token: _,
            use_encryption,
            use_compression,
        } = self;
        crate::config::ProxyConfig {
            name: proxy_name
                .clone()
                .or_else(|| server_name.clone())
                .unwrap_or_else(|| "xtcp-proxy".into()),
            proxy_type: "xtcp".into(),
            local_ip: local_ip.clone(),
            local_port: *local_port,
            sk: sk.clone(),
            use_encryption: *use_encryption,
            use_compression: *use_compression,
            ..Default::default()
        }
    }
}

impl SudpArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let Self {
            local_ip,
            local_port,
            remote_port,
            proxy_name,
            sk,
            server_addr: _,
            server_port: _,
            token: _,
            use_encryption,
            use_compression,
        } = self;
        crate::config::ProxyConfig {
            name: proxy_name
                .clone()
                .unwrap_or_else(|| format!("sudp-{}->{}", local_port, remote_port)),
            proxy_type: "sudp".into(),
            local_ip: local_ip.clone(),
            local_port: *local_port,
            remote_port: *remote_port,
            sk: sk.clone().unwrap_or_default(),
            use_encryption: *use_encryption,
            use_compression: *use_compression,
            ..Default::default()
        }
    }
}

impl TcpmuxArgs {
    pub fn to_proxy_config(&self) -> crate::config::ProxyConfig {
        let Self {
            local_ip,
            local_port,
            custom_domains,
            subdomain,
            mux,
            mux_port,
            proxy_name,
            server_addr: _,
            server_port: _,
            token: _,
            use_encryption,
            use_compression,
        } = self;
        crate::config::ProxyConfig {
            name: proxy_name
                .clone()
                .unwrap_or_else(|| format!("tcpmux-{}", local_port)),
            proxy_type: "tcpmux".into(),
            local_ip: local_ip.clone(),
            local_port: *local_port,
            custom_domains: custom_domains
                .clone()
                .map(|d| d.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
            subdomain: subdomain.clone().unwrap_or_default(),
            remote_port: *mux_port,
            multiplexer: mux.clone().unwrap_or_else(|| "httpconnect".into()),
            use_encryption: *use_encryption,
            use_compression: *use_compression,
            ..Default::default()
        }
    }
}
