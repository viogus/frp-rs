use super::*;

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
pub(crate) struct GoFlagRow {
    pub(crate) long: &'static str,
    pub(crate) short: Option<char>,
    pub(crate) varname: Option<&'static str>,
    pub(crate) usage: &'static str,
}

/// The `frps` root flag surface as one list: the 29 rows Go frp **v0.71.0**
/// prints, measured from the released darwin/arm64 binary (`frps --help`,
/// stdout, 2394 B), plus the two frp-rs extension flags that fill the same
/// structs.
///
/// The set is exactly the flags `frps verify --help` repeats under
/// `Global Flags` — i.e. Go's persistent `rootCmd` set, and the list a row here
/// is *missing* from is the interesting half: a flag absent from Go's persistent
/// set here is either an frp-rs extension ([`FRPS_EXTENSION_FLAGS`]) or a flag
/// frp-rs does not have.
///
/// Each row names the `FrpsArgs` field the flag fills, its type, and the cells
/// of Go's pflag row, and the rows are grouped under the bpaf `construct!`
/// struct that parses them. That is what the callback form buys — one list, two
/// shapes: `frps_go_flag_table` here emits [`FRPS_GO_FLAGS`], and
/// `frps_args_structs` in `frps.rs` emits `FrpsArgs`, the six `Svr*`
/// intermediates and the `FrpsBuild` -> `FrpsArgs` move, so the table and the
/// structs cannot describe different flag sets. A row with no `go ( … )` cell is
/// an frp-rs extension: it has a field, but its table row lives in
/// [`FRPS_EXTENSION_FLAGS`] because Go has no flag of that name.
///
/// Grouping means the rows are **not** in pflag's byte order as a whole (each
/// group keeps its struct's field order). Nothing reads the table positionally:
/// the renderer sorts by long (`frp-core/src/cli/help_render.rs:233`), so the
/// rendered document and its `--help` pins are unaffected, and a diff against
/// the measurement compares sorted long names.
///
/// Two of Go's rows describe flags frp-rs registers only under a feature:
/// `--kcp-bind-port` (`#[cfg(feature = "kcp")]`) and `--quic-bind-port`
/// (`#[cfg(feature = "quic")]`) in `frps::svr_transport`. The gate sits inside
/// the `go ( … )` cell and gates that table row only: a build without the
/// feature does not register the flag, so it is not part of that build's
/// persistent set and must not be expected under `Global Flags`. The struct
/// field stays in every build — `construct!` must name every field the parser
/// fills, and the parser substitutes `pure(None)` when the feature is off. With
/// frp-core's default features on all 29 rows are present, which is the shape
/// [`FRPS_GO_FLAGS`] was measured in.
macro_rules! frps_flag_specs {
    ($expand:ident) => {
        $expand! {
            SvrMeta as meta {
                (
                    /// Config file path. `None` when `-c` was not given (default
                    /// "frps.toml" is applied by [`FrpsArgs::config_path`]).
                    /// Go frp v0.70.1 parity: when `-c` is given the file is authoritative
                    /// and CLI config flags are ignored (audit task 9 finding 5).
                    config: Option<String>,
                    go ( long: "config", short: Some('c'), varname: Some("string"), usage: "config file of frps" )
                ),
                ( config_dir: Option<String> ),
                ( strict_config: bool, go ( long: "strict-config", short: None, varname: None, usage: "strict config parsing mode, unknown fields will cause errors (default true)" ) ),
                ( show_version: bool, go ( long: "version", short: Some('v'), varname: None, usage: "version of frps" ) ),
            }
            SvrBind as bind {
                ( bind_addr: Option<String>, go ( long: "bind-addr", short: None, varname: Some("string"), usage: "bind address (default \"0.0.0.0\")" ) ),
                ( bind_port: Option<u16>, go ( long: "bind-port", short: Some('p'), varname: Some("int"), usage: "bind port (default 7000)" ) ),
                ( proxy_bind_addr: Option<String>, go ( long: "proxy-bind-addr", short: None, varname: Some("string"), usage: "proxy bind address (default \"0.0.0.0\")" ) ),
            }
            SvrAuth as auth {
                ( token: Option<String>, go ( long: "token", short: Some('t'), varname: Some("string"), usage: "auth token" ) ),
                ( allow_ports: Option<String>, go ( long: "allow-ports", short: None, varname: Some("string"), usage: "allow ports" ) ),
                ( allow_unsafe: Vec<String>, go ( long: "allow-unsafe", short: None, varname: Some("strings"), usage: "allowed unsafe features, one or more of: TokenSourceExec" ) ),
            }
            SvrDashboard as dash {
                ( dashboard_addr: Option<String>, go ( long: "dashboard-addr", short: None, varname: Some("string"), usage: "dashboard address (default \"0.0.0.0\")" ) ),
                ( dashboard_port: Option<u16>, go ( long: "dashboard-port", short: None, varname: Some("int"), usage: "dashboard port" ) ),
                ( dashboard_user: Option<String>, go ( long: "dashboard-user", short: None, varname: Some("string"), usage: "dashboard user (default \"admin\")" ) ),
                ( dashboard_pwd: Option<String>, go ( long: "dashboard-pwd", short: None, varname: Some("string"), usage: "dashboard password (default \"admin\")" ) ),
                ( dashboard_tls_cert_file: Option<String>, go ( long: "dashboard-tls-cert-file", short: None, varname: Some("string"), usage: "dashboard tls cert file" ) ),
                ( dashboard_tls_key_file: Option<String>, go ( long: "dashboard-tls-key-file", short: None, varname: Some("string"), usage: "dashboard tls key file" ) ),
                ( dashboard_tls_mode: bool, go ( long: "dashboard-tls-mode", short: None, varname: None, usage: "if enable dashboard tls mode" ) ),
                ( enable_prometheus: bool, go ( long: "enable-prometheus", short: None, varname: None, usage: "enable prometheus dashboard" ) ),
            }
            SvrLog as log {
                ( disable_log_color: bool, go ( long: "disable-log-color", short: None, varname: None, usage: "disable log color in console" ) ),
                ( log_file: Option<String>, go ( long: "log-file", short: None, varname: Some("string"), usage: "log file (default \"console\")" ) ),
                ( log_level: Option<String>, go ( long: "log-level", short: None, varname: Some("string"), usage: "log level (default \"info\")" ) ),
                ( log_max_days: Option<i32>, go ( long: "log-max-days", short: None, varname: Some("int"), usage: "log max days (default 3)" ) ),
                ( log_format: Option<String> ),
            }
            SvrTransport as transport {
                ( kcp_bind_port: Option<u16>, go ( #[cfg(feature = "kcp")] long: "kcp-bind-port", short: None, varname: Some("int"), usage: "kcp bind udp port" ) ),
                ( quic_bind_port: Option<u16>, go ( #[cfg(feature = "quic")] long: "quic-bind-port", short: None, varname: Some("int"), usage: "quic bind udp port" ) ),
                ( max_ports_per_client: Option<u64>, go ( long: "max-ports-per-client", short: None, varname: Some("int"), usage: "max ports per client" ) ),
                ( subdomain_host: Option<String>, go ( long: "subdomain-host", short: None, varname: Some("string"), usage: "subdomain host" ) ),
                ( tls_only: bool, go ( long: "tls-only", short: None, varname: None, usage: "frps tls only" ) ),
                ( vhost_http_port: Option<u16>, go ( long: "vhost-http-port", short: None, varname: Some("int"), usage: "vhost http port" ) ),
                ( vhost_https_port: Option<u16>, go ( long: "vhost-https-port", short: None, varname: Some("int"), usage: "vhost https port" ) ),
                (
                    /// VHost HTTP response-header timeout, in seconds. Go frp registers this as
                    /// a **persistent root flag** with default 60
                    /// (`cmd.PersistentFlags().Int64VarP(&c.VhostHTTPTimeout, "vhost_http_timeout", "", 60, …)`,
                    /// `pkg/config/flags.go:237`), so `frps verify` inherits it too. `None`
                    /// means the flag was absent and the config value stands;
                    /// `ServerConfig::default()` already carries Go's 60
                    /// (`frp-core/src/config/server.rs:259`), so the absent case is Go's default.
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
                    vhost_http_timeout: Option<i64>,
                    go ( long: "vhost-http-timeout", short: None, varname: Some("int"), usage: "vhost http response header timeout (default 60)" )
                ),
            }
        }
    };
}

pub(crate) use frps_flag_specs;

/// `frps_flag_specs`' table arm: the rows' `go ( … )` cells become
/// [`FRPS_GO_FLAGS`]. A row without one is an frp-rs extension and contributes
/// no table row here.
///
/// Its pattern mirrors `frps_args_structs` in `frps.rs`: both open the same
/// list, so a change to the row shape has to change both.
macro_rules! frps_go_flag_table {
    (
        $( $sname:ident as $acc:ident {
            $( ( $(#[$doc:meta])* $field:ident : $ty:ty $(, go ( $(#[$gate:meta])* long: $long:literal, short: $short:expr, varname: $varname:expr, usage: $usage:literal ) )? ) ),* $(,)?
        } )+
    ) => {
        pub(crate) const FRPS_GO_FLAGS: &[GoFlagRow] = &[
            $( $(
                $( $(#[$gate])* GoFlagRow { long: $long, short: $short, varname: $varname, usage: $usage }, )?
            )* )+
        ];
    };
}

frps_flag_specs!(frps_go_flag_table);

/// `frpc`'s persistent root flags, measured the same way (`frpc --help`,
/// 1370 B; `frpc verify --help` repeats exactly these under `Global Flags`).
pub(crate) const FRPC_ROOT_GO_FLAGS: &[GoFlagRow] = &[
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
pub(crate) const FRPC_ADMIN_GO_FLAGS: &[GoFlagRow] = &[GoFlagRow {
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
pub(crate) const FRPC_PROXY_GO_FLAGS: &[GoFlagRow] = &[
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
pub(crate) const FRPS_EXTENSION_FLAGS: &[GoFlagRow] = &[
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
pub(crate) const FRPC_ROOT_EXTENSION_FLAGS: &[GoFlagRow] = &[
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
pub(crate) const FRPC_ADMIN_EXTENSION_FLAGS: &[GoFlagRow] = &[
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
pub(crate) const FRPC_PROXY_EXTENSION_FLAGS: &[GoFlagRow] = &[
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
pub(crate) const FRPS_DESCR: &str = "frps is the server of frp (https://github.com/fatedier/frp)";

pub(crate) const FRPC_DESCR: &str = "frpc is the client of frp (https://github.com/fatedier/frp)";

/// Go's `Short` text for each implemented child command, as both the
/// `Available Commands:` line and (for a leaf) the document's first line.
///
/// `Verify that the configures is valid` is **Go's own typo** — it reads
/// "configures" for "configuration" — and it is what the released v0.71.0
/// binary prints on `frps verify --help` and `frpc verify --help` alike. Those
/// two documents are the byte-exact witness for this layer, so the typo is
/// load-bearing: do not "fix" it.
pub(crate) const FRPS_COMMAND_SHORTS: &[(&str, &str)] =
    &[("verify", "Verify that the configures is valid")];

pub(crate) const FRPC_COMMAND_SHORTS: &[(&str, &str)] = &[
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
pub(crate) fn root_name(root: RootCommand) -> &'static str {
    match root {
        RootCommand::Frps => "frps",
        RootCommand::Frpc => "frpc",
    }
}

pub(crate) fn root_descr(root: RootCommand) -> &'static str {
    match root {
        RootCommand::Frps => FRPS_DESCR,
        RootCommand::Frpc => FRPC_DESCR,
    }
}

/// Go's short text for one of this root's commands; empty when the command has
/// no measured text (which the module tests reject).
pub(crate) fn command_short(root: RootCommand, command: &str) -> &'static str {
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
pub(crate) fn root_persistent_flags(root: RootCommand) -> &'static [GoFlagRow] {
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
pub(crate) fn help_flag_tables(
    root: RootCommand,
    command: Option<&str>,
) -> Vec<&'static [GoFlagRow]> {
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
