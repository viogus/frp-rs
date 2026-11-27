use std::ffi::OsString;

use bpaf::Parser;
use bpaf::*;

use super::*;

// ──────────────────────────────────────────────────────────────────────
// frps CLI — 30+ flags
// ──────────────────────────────────────────────────────────────────────

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

/// `frps_flag_specs`' struct arm: the rows become the parser's structs.
///
/// `FrpsArgs` is what the flags fill and what `parse_frps_args` returns; the six
/// `Svr*` structs are bpaf `construct!` intermediates (each within the field
/// limit) and `FrpsBuild` composes them. `From<FrpsBuild>` moves every field
/// across, so a row that is in the list is in all three shapes or none.
///
/// Its pattern mirrors `frps_go_flag_table` in `flag_tables.rs`: both open the
/// same list, so a change to the row shape has to change both.
macro_rules! frps_args_structs {
    (
        $( $sname:ident as $acc:ident {
            $( ( $(#[$doc:meta])* $field:ident : $ty:ty $(, go ( $(#[$gate:meta])* long: $long:literal, short: $short:expr, varname: $varname:expr, usage: $usage:literal ) )? ) ),* $(,)?
        } )+
    ) => {
        /// CLI arguments for frps (server).
        ///
        /// Fields that can also appear in the config file use `Option<T>`: `Some`
        /// means the user explicitly passed the flag on the CLI and it should
        /// override the config value.  `None` means the config value is used.
        #[derive(Debug, Clone)]
        pub struct FrpsArgs {
            $( $( $(#[$doc])* pub $field: $ty, )* )+
        }

        // Intermediate builder structs — each within bpaf construct! field limits.
        $(
            pub(crate) struct $sname {
                $( $field: $ty, )*
            }
        )+

        // Composed builder: these 6 parsers feed into the final FrpsArgs.
        pub(crate) struct FrpsBuild {
            $( $acc: $sname, )+
        }

        impl From<FrpsBuild> for FrpsArgs {
            fn from(b: FrpsBuild) -> Self {
                FrpsArgs {
                    $( $( $field: b.$acc.$field, )* )+
                }
            }
        }
    };
}

frps_flag_specs!(frps_args_structs);

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
pub(crate) fn svr_config() -> impl Parser<Option<String>> {
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
pub(crate) fn svr_config_dir() -> impl Parser<Option<String>> {
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
pub(crate) fn svr_log_format() -> impl Parser<Option<String>> {
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
pub(crate) struct FrpsRootSlots<C, D, L> {
    config: C,
    config_dir: D,
    log_format: L,
}

/// The four root flags [`SvrMeta`] carries. The two config-selecting parsers are
/// parameters because the run path and the `verify` subcommand differ in those;
/// everything else is shared, so the two surfaces cannot drift.
pub(crate) fn svr_meta(
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

pub(crate) fn svr_bind() -> impl Parser<SvrBind> {
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

pub(crate) fn svr_auth() -> impl Parser<SvrAuth> {
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

pub(crate) fn svr_dashboard() -> impl Parser<SvrDashboard> {
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
pub(crate) fn svr_log(log_format: impl Parser<Option<String>>) -> impl Parser<SvrLog> {
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

pub(crate) fn svr_transport() -> impl Parser<SvrTransport> {
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

pub(crate) fn frps_build(
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
pub(crate) fn frps_parser() -> impl Parser<FrpsCmd> {
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
pub(crate) fn frps_verify_cmd() -> impl Parser<FrpsCmd> {
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
        // Exhaustive on purpose: every field the row list generates is named
        // here, so a row added to `frps_flag_specs` without an overlay decision
        // fails to compile (`E0027`) instead of being parsed and then ignored.
        // The compiler asks for a decision, not a correct one — `config: _`
        // compiles — so the discarded bindings below each say where the value
        // is consumed instead, and the applied ones are read from the bindings
        // rather than from `self`. The strongest case is a row that arrives
        // with its parser arm: `dashboard_user: _` for a flag the overlay
        // should have applied compiles and is caught by no test unless the
        // overlay is witnessed field by field.
        // The seven rows this overlay does not apply, and where each is read
        // instead: `config`/`strict_config` by `FrpsArgs::config_path` (the
        // loader's input and its strict-parse decision), `config_dir` by
        // `FrpsArgs::cli_overrides_enabled` and the config-dir lane
        // (`frps/src/main.rs:656`), `show_version` at `frps/src/main.rs:645-647`
        // (printed, never merged), `allow_unsafe` at `frps/src/main.rs:651`,
        // `disable_log_color` at `frps/src/main.rs:606`, and
        // `dashboard_tls_mode`, which has no effective field:
        // `web_server.tls.enable` is inert (`frp-core/src/config/server.rs:975`)
        // and TLS is decided by the two files
        // (`frp-server/src/dashboard.rs:3843`).
        let Self {
            config: _,
            config_dir: _,
            strict_config: _,
            show_version: _,
            allow_unsafe: _,
            disable_log_color: _,
            dashboard_tls_mode: _,
            bind_addr,
            bind_port,
            proxy_bind_addr,
            token,
            allow_ports,
            dashboard_addr,
            dashboard_port,
            dashboard_user,
            dashboard_pwd,
            dashboard_tls_cert_file,
            dashboard_tls_key_file,
            enable_prometheus,
            log_file,
            log_level,
            log_max_days,
            log_format,
            subdomain_host,
            tls_only,
            kcp_bind_port,
            quic_bind_port,
            vhost_http_port,
            vhost_https_port,
            vhost_http_timeout,
            max_ports_per_client,
        } = self;
        // A build without the listener still carries the field (the struct is
        // feature-independent, the parser substitutes `pure(None)`), so the
        // binding is unused in that build by design.
        #[cfg(not(feature = "kcp"))]
        let _ = kcp_bind_port;
        #[cfg(not(feature = "quic"))]
        let _ = quic_bind_port;

        let mut applied = crate::config::AppliedReaderGatedPorts::default();
        if let Some(ref v) = token {
            cfg.auth.token = v.clone();
        }
        if let Some(ref v) = allow_ports {
            cfg.allow_ports = v.clone();
        }
        if let Some(ref v) = bind_addr {
            cfg.bind_addr = v.clone();
        }
        if let Some(v) = bind_port {
            cfg.bind_port = *v;
        }
        if let Some(ref v) = proxy_bind_addr {
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
        if let Some(ref v) = log_file {
            if !v.is_empty() {
                cfg.log.file = v.clone();
            }
        }
        if let Some(ref v) = log_level {
            if !v.is_empty() {
                cfg.log.level = v.clone();
            }
        }
        if let Some(v) = log_max_days {
            if *v != 0 {
                cfg.log.max_days = *v;
            }
        }
        // `--log-format` has no `LogConfig::complete` slot and no Go analogue
        // on the file lane, so it keeps the raw write-through; see the
        // `log_flag_zero_values_do_not_override_the_config_file` pin below.
        if let Some(ref v) = log_format {
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
        if let Some(v) = kcp_bind_port {
            cfg.kcp_bind_port = *v;
            applied.kcp_bind_port = *v != 0;
        }
        #[cfg(feature = "quic")]
        if let Some(v) = quic_bind_port {
            cfg.quic_bind_port = *v;
            applied.quic_bind_port = *v != 0;
        }
        if let Some(v) = vhost_http_port {
            cfg.vhost_http_port = *v;
        }
        if let Some(v) = vhost_https_port {
            cfg.vhost_https_port = *v;
        }
        if let Some(v) = vhost_http_timeout {
            cfg.vhost_http_timeout = *v;
        }
        if let Some(ref v) = subdomain_host {
            cfg.sub_domain_host = v.clone();
        }
        if let Some(v) = max_ports_per_client {
            cfg.max_ports_per_client = *v;
        }
        if *tls_only {
            cfg.tls_only = true;
        }

        // Dashboard
        if let Some(ref v) = dashboard_addr {
            cfg.web_server.addr = v.clone();
        }
        if let Some(v) = dashboard_port {
            cfg.web_server.port = *v;
            // A zero port is "not supplied" on the file path too
            // (`sub_port_requested`); only a real request is reported, so
            // `--dashboard-port 0` stays as silent as `port = 0`.
            applied.web_server_port = *v != 0;
        }
        if let Some(ref v) = dashboard_user {
            cfg.web_server.user = v.clone();
        }
        if let Some(ref v) = dashboard_pwd {
            cfg.web_server.password = v.clone();
        }
        if *enable_prometheus {
            cfg.web_server.enable_prometheus = true;
        }
        if let Some(ref v) = dashboard_tls_cert_file {
            cfg.web_server.tls_cert_file = v.clone();
        }
        if let Some(ref v) = dashboard_tls_key_file {
            cfg.web_server.tls_key_file = v.clone();
        }
        // dashboard_tls_mode: no config field needed — TLS activates when both
        // cert_file and key_file are non-empty (implicit detection, matching Go frp).
        applied
    }
}
