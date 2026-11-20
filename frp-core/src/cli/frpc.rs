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

// ─── Subcommand parsers (inlined — bpaf construct! doesn't support destructuring tuples from parser fns) ───
pub(crate) fn tcp_cmd() -> impl Parser<FrpcCmd> {
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

pub(crate) fn udp_cmd() -> impl Parser<FrpcCmd> {
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

pub(crate) fn http_cmd() -> impl Parser<FrpcCmd> {
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

pub(crate) fn https_cmd() -> impl Parser<FrpcCmd> {
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

pub(crate) fn stcp_cmd() -> impl Parser<FrpcCmd> {
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

pub(crate) fn xtcp_cmd() -> impl Parser<FrpcCmd> {
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

pub(crate) fn sudp_cmd() -> impl Parser<FrpcCmd> {
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

pub(crate) fn tcpmux_cmd() -> impl Parser<FrpcCmd> {
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
    // (frp-core/src/config/client.rs:1142) is where it lands. A literal
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
