use bpaf::Parser;
use std::ffi::OsString;

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
    for ((label, root, command, rendered, go), full) in SURFACES.into_iter().zip(SURFACE_DOCUMENTS)
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
/// The admin tables' membership, pinned by name.
///
/// The admin surface is the one family where the two tables are *not* covered by
/// a rendered-document pin: an `ext` row moved into the Go table (or one row
/// carrying both cells) compiles, renders identically — the renderer does not
/// care which table answered — and leaves every `--help` pin green. What it
/// does change is the parity claim the table makes, so it is asserted here
/// rather than left to a diff read.
#[test]
fn the_admin_tables_name_exactly_the_flags_each_side_registers() {
    let go: Vec<&str> = FRPC_ADMIN_GO_FLAGS.iter().map(|row| row.long).collect();
    assert_eq!(
        go,
        ["api-timeout"],
        "Go registers exactly one flag on the admin commands (cmd/frpc/sub/admin.go)"
    );
    let ext: std::collections::BTreeSet<&str> = FRPC_ADMIN_EXTENSION_FLAGS
        .iter()
        .map(|row| row.long)
        .collect();
    assert_eq!(
        ext,
        [
            "admin-addr",
            "admin-port",
            "admin-pwd",
            "admin-user",
            "json"
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>(),
        "the five flags frp-rs adds on top of Go's"
    );
    assert!(
        go.iter().all(|long| !ext.contains(long)),
        "no flag may be claimed by both tables"
    );
}

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
        let expected_longs: std::collections::BTreeSet<&str> = expected.keys().copied().collect();
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
