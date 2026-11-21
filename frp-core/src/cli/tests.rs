use bpaf::Parser;
use std::ffi::OsString;
use std::time::Duration;

use super::*;

/// The `frps` **run-path** parser, which is `frps_args()` — the module's
/// flag-surface tests want the root command's own arguments, and driving
/// them through [`frps_parser`]'s alternation would let the `verify` branch
/// answer for a run-mode argv. The whole surface is `frps_parser()`; the
/// hoist tests below use [`run_frps_cmd`] for it.
fn parse_frps(args: &[&str]) -> Result<FrpsArgs, bpaf::ParseFailure> {
    frps_args().to_options().run_inner(args)
}

fn parse_frps_verify(args: &[&str]) -> Result<VerifyArgs, bpaf::ParseFailure> {
    match frps_parser().to_options().run_inner(args)? {
        FrpsCmd::Verify(a) => Ok(a),
        other => panic!("expected the frps verify command, got {other:?}"),
    }
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

/// `frpc tcp` — used by the `GO_BOOL_SITES` rows, which exercise Go's
/// `--ue`/`--uc` (and their frp-rs aliases) on this one surface; every proxy
/// surface takes them, and that is pinned separately by
/// [`every_proxy_surface_accepts_go_bool_names_and_their_frp_rs_aliases`].
fn parse_frpc_tcp(args: &[&str]) -> Result<TcpArgs, bpaf::ParseFailure> {
    match frpc_parser().to_options().run_inner(args)? {
        FrpcCmd::Tcp(a) => Ok(a),
        other => panic!("expected tcp command, got {other:?}"),
    }
}

/// Parse any `frpc <proxy>` command line and hand back the whole command, so
/// a probe can cover the surfaces that have no dedicated helper.
fn parse_frpc_proxy(args: &[&str]) -> Result<FrpcCmd, bpaf::ParseFailure> {
    frpc_parser().to_options().run_inner(args)
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

/// The `--allow-unsafe` reader on its own ([`allow_unsafe_parser`]), so a
/// test can compare the **values** pflag would see instead of only whether a
/// command accepted the argv.
fn read_allow_unsafe(args: &[&str]) -> Result<Vec<String>, bpaf::ParseFailure> {
    allow_unsafe_parser().to_options().run_inner(args)
}

/// The ignored twin on its own ([`ignored_allow_unsafe`]): the value is
/// dropped on the surfaces that use it, but it must still be read — and
/// refused when malformed — exactly like [`read_allow_unsafe`].
fn read_ignored_allow_unsafe(args: &[&str]) -> Result<Vec<String>, bpaf::ParseFailure> {
    ignored_allow_unsafe().to_options().run_inner(args)
}

/// Every parser that accepts `--strict-config`, as `(label, argv)` —
/// `frps`'s run path, `frps verify`, then `frpc`'s `run`/`verify`/`reload`/
/// `status`/`stop`. `-c x.toml` is present throughout because both `verify`
/// commands need a config path in the argv; the other five fall back and
/// never read the file (these helpers only run the bpaf parser).
///
/// `frps verify` belongs in this table: Go registers `--strict_config` on
/// `frps`'s **root** command (`cmd/frps/root.go:46`) and `verifyCmd` reads
/// it (`cmd/frps/verify.go:40`), so it is the same persistent pflag and must
/// take the same spellings and the same default. The table's purpose is
/// exactly that "one flag, every parser" claim, and leaving the new parser
/// out would let it drift silently.
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
        ("frps verify", prefixed("verify")),
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
        "frps verify" => parse_frps_verify(&a).map(|x| x.strict_config),
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

/// `--dashboard-port` is the one reader-gated listener port the CLI overlay
/// can write, so its request has to travel back to the caller on
/// [`AppliedReaderGatedPorts`] — `web_server.port` is unconditional in
/// `ServerConfig`, and the overlay runs after the load that records the
/// *file's* request, so a returned value is the only way `frps` can hand it
/// to the same warn path.
///
/// The zero case matters as much as the non-zero one: the file path counts
/// only a **non-zero** port (`sub_port_requested`), so `--dashboard-port 0`
/// must not manufacture a record the file form would never produce. Pinned
/// on the real binary by
/// `frps/tests/warn_delivery.rs::web_server_port_warning_reaches_a_flag_user_without_a_config`.
///
/// [`AppliedReaderGatedPorts`]: crate::config::AppliedReaderGatedPorts
#[test]
fn dashboard_port_override_reports_the_reader_gated_request() {
    let mut cfg = crate::config::ServerConfig::default();
    let applied = parse_frps(&["--dashboard-port", "7500"])
        .unwrap()
        .override_server_config(&mut cfg);
    assert_eq!(
        cfg.web_server.port, 7500,
        "the flag still reaches the config"
    );
    assert!(
        applied.web_server_port,
        "a non-zero --dashboard-port is an applied reader-gated port"
    );

    let mut cfg = crate::config::ServerConfig::default();
    let applied = parse_frps(&["--dashboard-port", "0"])
        .unwrap()
        .override_server_config(&mut cfg);
    assert_eq!(cfg.web_server.port, 0);
    assert!(
        !applied.web_server_port,
        "`--dashboard-port 0` is Go's zero value, exactly like `port = 0` in a file: \
         it requests no listener, so it must not warn"
    );

    let mut cfg = crate::config::ServerConfig::default();
    let applied = parse_frps(&[]).unwrap().override_server_config(&mut cfg);
    assert_eq!(cfg.web_server.port, 0);
    assert!(!applied.web_server_port, "no flag at all is not a request");
}

/// The merge `frps` performs at startup: an overlay-applied
/// `web_server.port` becomes the same record as the file key, and only in a
/// build whose reader is absent. The per-shape half of this claim is pinned
/// by `frp-server/src/service.rs::dashboard_port_overlay_record_follows_this_builds_reader`
/// (which uses the owning crate's real reader) and on the binary by
/// `frps/tests/warn_delivery.rs`.
#[test]
fn recorded_overlay_port_warns_only_when_the_reader_is_absent() {
    use crate::config::{AppliedReaderGatedPorts, ConfigPresence, ListenerPortReader};

    let mut presence = ConfigPresence::default();
    presence.record_applied_reader_gated_ports(AppliedReaderGatedPorts {
        web_server_port: true,
        ..Default::default()
    });
    assert_eq!(
        presence.unhonoured_reader_gated_port_records(
            ListenerPortReader::Absent,
            ListenerPortReader::Present
        ),
        vec![crate::config::WEB_SERVER_PORT_UNHONOURED_WARNING],
        "an overlay-applied port in a build without the reader is a record"
    );
    assert!(
        presence
            .unhonoured_reader_gated_port_records(
                ListenerPortReader::Present,
                ListenerPortReader::Present
            )
            .is_empty(),
        "a build that binds the port must stay silent"
    );

    let mut presence = ConfigPresence::default();
    presence.record_applied_reader_gated_ports(AppliedReaderGatedPorts::default());
    assert!(
        presence
            .unhonoured_reader_gated_port_records(
                ListenerPortReader::Absent,
                ListenerPortReader::Absent
            )
            .is_empty(),
        "recording nothing must add nothing"
    );
}

/// The `--kcp-bind-port` twin of
/// [`dashboard_port_override_reports_the_reader_gated_request`]: the overlay
/// writes `kcp_bind_port` **and** reports the request, and the zero value is
/// not a request. Without the report,
/// `frps --kcp-bind-port 7100` (no `-c`) in the hand-named shape
/// (`tiny,frp-core/kcp`, where this crate has the flag but `frp-server` has
/// no listener) binds nothing and says nothing.
#[cfg(feature = "kcp")]
#[test]
fn kcp_bind_port_override_reports_the_reader_gated_request() {
    for spelling in ["--kcp-bind-port", "--kcp_bind_port"] {
        let mut cfg = crate::config::ServerConfig::default();
        let applied = parse_frps(&[spelling, "7100"])
            .unwrap()
            .override_server_config(&mut cfg);
        assert_eq!(
            cfg.kcp_bind_port, 7100,
            "`{spelling}` must reach the config"
        );
        assert!(
            applied.kcp_bind_port,
            "a non-zero `{spelling}` is an applied listener port"
        );
    }

    let mut cfg = crate::config::ServerConfig::default();
    let applied = parse_frps(&["--kcp-bind-port", "0"])
        .unwrap()
        .override_server_config(&mut cfg);
    assert_eq!(cfg.kcp_bind_port, 0);
    assert!(
        !applied.kcp_bind_port,
        "`--kcp-bind-port 0` is Go's zero value, exactly like `kcp_bind_port = 0` \
         in a file: it requests no listener, so it must not warn"
    );

    let mut cfg = crate::config::ServerConfig::default();
    let applied = parse_frps(&[]).unwrap().override_server_config(&mut cfg);
    assert_eq!(cfg.kcp_bind_port, 0);
    assert!(!applied.kcp_bind_port, "no flag at all is not a request");
}

/// The `--quic-bind-port` twin of
/// [`kcp_bind_port_override_reports_the_reader_gated_request`].
#[cfg(feature = "quic")]
#[test]
fn quic_bind_port_override_reports_the_reader_gated_request() {
    for spelling in ["--quic-bind-port", "--quic_bind_port"] {
        let mut cfg = crate::config::ServerConfig::default();
        let applied = parse_frps(&[spelling, "7200"])
            .unwrap()
            .override_server_config(&mut cfg);
        assert_eq!(
            cfg.quic_bind_port, 7200,
            "`{spelling}` must reach the config"
        );
        assert!(
            applied.quic_bind_port,
            "a non-zero `{spelling}` is an applied listener port"
        );
    }

    let mut cfg = crate::config::ServerConfig::default();
    let applied = parse_frps(&["--quic-bind-port", "0"])
        .unwrap()
        .override_server_config(&mut cfg);
    assert_eq!(cfg.quic_bind_port, 0);
    assert!(
        !applied.quic_bind_port,
        "`--quic-bind-port 0` is Go's zero value, exactly like `quic_bind_port = 0` \
         in a file: it requests no listener, so it must not warn"
    );

    let mut cfg = crate::config::ServerConfig::default();
    let applied = parse_frps(&[]).unwrap().override_server_config(&mut cfg);
    assert_eq!(cfg.quic_bind_port, 0);
    assert!(!applied.quic_bind_port, "no flag at all is not a request");
}

/// The `frp-core`-gated half of the overlay merge, the counterpart of
/// [`recorded_overlay_port_warns_only_when_the_reader_is_absent`]: an
/// overlay-applied `kcp_bind_port` / `quic_bind_port` becomes the same record
/// as the file key, and only when the caller reports no listener for it.
///
/// `websocket_port` is deliberately absent: there is no
/// `--websocket-port` flag, so it has no overlay half and
/// `AppliedReaderGatedPorts` carries no field for it.
#[cfg(all(feature = "kcp", feature = "quic"))]
#[test]
fn recorded_overlay_gated_ports_warn_only_when_the_reader_is_absent() {
    use crate::config::{
        AppliedReaderGatedPorts, ConfigPresence, GatedListenerPortReaders, ListenerPortReader,
    };

    let applied = AppliedReaderGatedPorts {
        kcp_bind_port: true,
        quic_bind_port: true,
        ..Default::default()
    };
    let no_readers = GatedListenerPortReaders::from_features(false, false, false);
    let all_readers = GatedListenerPortReaders::from_features(true, true, true);

    let mut presence = ConfigPresence::default();
    presence.record_applied_reader_gated_ports(applied);
    let records = presence.unhonoured_server_feature_key_records(no_readers);
    assert_eq!(
        records,
        vec![
            crate::config::SERVER_KCP_BIND_PORT_UNHONOURED_NO_READER_WARNING.clone(),
            crate::config::SERVER_QUIC_BIND_PORT_UNHONOURED_NO_READER_WARNING.clone(),
        ],
        "an overlay-applied gated port in a build without its listener is a record"
    );
    assert!(
        presence
            .unhonoured_server_feature_key_records(all_readers)
            .is_empty(),
        "a build that binds both ports must stay silent"
    );

    let mut presence = ConfigPresence::default();
    presence.record_applied_reader_gated_ports(AppliedReaderGatedPorts::default());
    assert!(
        presence
            .unhonoured_server_feature_key_records(no_readers)
            .is_empty(),
        "recording nothing must add nothing"
    );
    // The assertion has to be able to fail: the two reader values must be
    // distinguishable, or every comparison above holds vacuously.
    assert_ne!(ListenerPortReader::Present, ListenerPortReader::Absent);
}

/// `--vhost-http-timeout` is Go's `vhost_http_timeout`, registered on the
/// persistent root so it is accepted on both the run and `verify` paths.
/// This pins the parts a parse-only check would miss: the value reaches
/// `ServerConfig` on the override lane, and an absent flag leaves Go's
/// default (60, `frp-core/src/config/server.rs:249`) alone.
#[test]
fn vhost_http_timeout_flag_applied_to_server_config() {
    for spelling in ["--vhost-http-timeout", "--vhost_http_timeout"] {
        let args = parse_frps(&[spelling, "30"]).unwrap();
        assert_eq!(
            args.vhost_http_timeout,
            Some(30),
            "`{spelling} 30` must parse as 30"
        );
        let mut cfg = crate::config::ServerConfig::default();
        args.override_server_config(&mut cfg);
        assert_eq!(cfg.vhost_http_timeout, 30, "`{spelling}` must be applied");
    }

    let args = parse_frps(&[]).unwrap();
    assert_eq!(args.vhost_http_timeout, None);
    let mut cfg = crate::config::ServerConfig::default();
    args.override_server_config(&mut cfg);
    assert_eq!(cfg.vhost_http_timeout, 60, "absent flag keeps Go's default");

    // Go registers the flag with `Int64VarP` (`pkg/config/flags.go:237`) and
    // its config field is `int64`, so the signed boundaries are accepted and
    // only a value outside `int64` is refused. Measured on Go v0.71.0
    // (`frps verify -c <valid>`): `-1` and `-9223372036854775808` rc 0,
    // `9223372036854775807` rc 0, `9223372036854775808` and
    // `9999999999999999999` rc 1 `strconv.ParseInt … value out of range`.
    //
    // A `-`-prefixed value needs the same preparation the binaries run
    // ([`prepared_cli_argv`], `attach_flag_shaped_values`): bpaf alone reads
    // `-1` as a flag, which is why the real `frps --vhost-http-timeout -1`
    // parses (measured: it starts and exits on the config's own error, not
    // on argv).
    let parse_prepared = |argv: &[&str]| {
        let prepared: Vec<OsString> = argv.iter().map(OsString::from).collect();
        frps_args()
            .to_options()
            .run_inner(&prepared_cli_argv(&prepared, RootCommand::Frps)[..])
    };
    for (argv, expected) in [
        ("-1", -1_i64),
        ("-9223372036854775808", i64::MIN),
        ("9223372036854775807", i64::MAX),
    ] {
        let args = parse_prepared(&["--vhost-http-timeout", argv]).unwrap();
        assert_eq!(
            args.vhost_http_timeout,
            Some(expected),
            "`{argv}` is inside Go's int64 range"
        );
        let mut cfg = crate::config::ServerConfig::default();
        args.override_server_config(&mut cfg);
        assert_eq!(
            cfg.vhost_http_timeout, expected,
            "`{argv}` must reach the config signed, not refused or wrapped"
        );
    }
    for argv in ["9223372036854775808", "9999999999999999999"] {
        assert!(
            parse_prepared(&["--vhost-http-timeout", argv]).is_err(),
            "`{argv}` is outside Go's int64, so `Int64VarP` refuses it too"
        );
    }
}

/// `--log-level ""`, `--log-file ""` and `--log-max-days 0` are Go's zero
/// values, and `LogConfig::complete` fills them with `info`/`console`/`3`
/// (`frp-core/src/config/server.rs`). Writing them through this override
/// therefore silently **raised** a config file's explicit
/// `[log] level = "warn"` back to `info` on the one lane that applies
/// overrides — on the pre-fix revision `3f66d823` (before `c8451157`),
/// frps run with `frps.toml` (`[log] level = "warn"`) in the cwd and no
/// `-c`: the empty flag was written into `[log] level` and completed to
/// `info`, so `--log-level ""` resolved to `info` (11 `INFO` records) where
/// no flag gave 0. That resolved-`info` output is the one this head binary
/// still prints for `--log-level info` on the same lane: 11 `INFO` records,
/// config `bindPort = 17531`, `[auth] token = "rev427token"`,
/// `[log] level = "warn"`.
/// Go v0.71.0 has no parity to claim on the *non-empty* value — with `-c`
/// it discards the pflag-bound struct, so its file's `warn` survives an
/// absent, empty **or** non-empty `--log-level` (0 records in all three) —
/// and frp-rs still honours a non-empty one (open divergence R1). The shape
/// this test pins is the *empty* value on the implicit `./frps.toml` lane,
/// where `--log-level ""` now keeps the file's `warn` (0 `INFO` records);
/// `frpc`, which never overlays, honoured the file throughout. The resolvers
/// already model the zero values as absent for both binaries
/// (`resolve_log_level`/`resolve_log_file`/`resolve_log_max_days`,
/// `frp-core/src/logging.rs:113`, `:152`, `:207`).
#[test]
fn log_flag_zero_values_do_not_override_the_config_file() {
    let mut cfg = crate::config::ServerConfig::default();
    cfg.log.level = "warn".to_string();
    cfg.log.file = "logs/frps.log".to_string();
    cfg.log.max_days = 5;

    let args = parse_frps(&["--log-level", "", "--log-file", "", "--log-max-days", "0"]).unwrap();
    // The zero values still parse as *supplied*: it is the overlay, not the
    // parser, that treats them as absent.
    assert_eq!(args.log_level.as_deref(), Some(""));
    assert_eq!(args.log_file.as_deref(), Some(""));
    assert_eq!(args.log_max_days, Some(0));
    args.override_server_config(&mut cfg);
    // The real order (`frps/src/main.rs`): override first, then Go's completion.
    cfg.complete();
    assert_eq!(
        cfg.log.level, "warn",
        "an empty --log-level is not supplied"
    );
    assert_eq!(
        cfg.log.file, "logs/frps.log",
        "an empty --log-file is not supplied"
    );
    assert_eq!(cfg.log.max_days, 5, "a zero --log-max-days is not supplied");

    // Non-zero flags still win, so this is a zero-value filter and not
    // "ignore the CLI log flags".
    let mut cfg = crate::config::ServerConfig::default();
    cfg.log.level = "warn".to_string();
    cfg.log.max_days = 5;
    let args = parse_frps(&["--log-level", "trace", "--log-max-days", "7"]).unwrap();
    args.override_server_config(&mut cfg);
    // The real order (`frps/src/main.rs`): override first, then Go's completion.
    cfg.complete();
    assert_eq!(cfg.log.level, "trace", "a non-empty --log-level still wins");
    assert_eq!(cfg.log.max_days, 7, "a non-zero --log-max-days still wins");

    // Deliberate residue, pinned so it cannot change silently:
    // `--log-format` has no `LogConfig::complete` slot (Go has no
    // completion for it either), so it keeps the raw write-through.
    let mut cfg = crate::config::ServerConfig::default();
    cfg.log.format = "json".to_string();
    let args = parse_frps(&["--log-format", ""]).unwrap();
    args.override_server_config(&mut cfg);
    // The real order (`frps/src/main.rs`): override first, then Go's completion.
    cfg.complete();
    assert_eq!(
        cfg.log.format, "",
        "--log-format keeps the raw write-through (no zero-value filter)"
    );

    // A negative `--log-max-days` is explicit on Go too
    // (`util.EmptyOr(-1, 3)` is `-1`) and must pass through: only the zero
    // value is filtered. The `=` spelling below is a property of the
    // raw-argv helpers (`parse_frps`, `parse_frps_run` and the other
    // test-local `run_inner` call sites), not of the binaries: they hand
    // tokens straight to `run_inner`, so bpaf sees them raw and refuses the
    // space form — measured, "`--log-max-days` requires an argument DAYS,
    // got a flag -1, try `--log-max-days=-1` to use it as an argument". The
    // binaries accept both spellings, because `prepared_cli_argv` runs
    // `attach_flag_shaped_values`, which hands a `-`-shaped next token to
    // any listed value-taking long flag before bpaf sees it
    // (`VALUE_TAKING_LONG_FLAGS`; see `claims_the_next_token`). No real entry
    // point reaches the raw path: the two production paths pass
    // `prepared_cli_argv` output into `run_cli`. Measured on the built
    // binary: `frps --log-max-days -1` and `frps --log-max-days=-1` both
    // start the listener and both leave a five-day-old rotation file alive
    // (`-1` disables cleanup), and `frps --log-max-days -x` fails with
    // "couldn't parse `-x`: invalid digit found in string" — the token did
    // arrive as the value.
    let mut cfg = crate::config::ServerConfig::default();
    cfg.log.max_days = 5;
    let args = parse_frps(&["--log-max-days=-1"]).unwrap();
    args.override_server_config(&mut cfg);
    // The real order (`frps/src/main.rs`): override first, then Go's completion.
    cfg.complete();
    assert_eq!(cfg.log.max_days, -1, "only the zero value is filtered");
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
    // The done-when for `TODO.md:3366` requires the divergence stated in
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
// 1 here (`TODO.md:3498`). The rows below are the parser half; the
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
    ("frpc tcp --ue", "--ue", Some("--use_encryption")),
    ("frpc tcp --uc", "--uc", Some("--use_compression")),
    ("frpc status --json", "--json", None),
];

/// Parse the flag under test on its own surface: the required positional
/// arguments of `frpc tcp`/`frpc status` are supplied, and the flag argv is
/// appended.
fn parse_site(site: &str, flag_argv: &[&str]) -> Result<bool, bpaf::ParseFailure> {
    let base: &[&str] = match site {
        "frpc tcp --ue" | "frpc tcp --uc" => &["tcp", "--local-port", "1", "--remote-port", "2"],
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
        "frpc tcp --ue" => parse_frpc_tcp(&argv).map(|a| a.use_encryption),
        "frpc tcp --uc" => parse_frpc_tcp(&argv).map(|a| a.use_compression),
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
        ("frpc tcp", "--ue", "use encryption", "go-bool"),
        ("frpc tcp", "--uc", "use compression", "go-bool"),
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
                format!("{meaning}. {name}=<bool> is an frp-rs extension: Go registers no {name}"),
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

/// Every proxy surface takes Go's `--ue`/`--uc` as the primary spelling and
/// keeps frp-rs's two older spellings on the same parser branch.
///
/// Go registers `use-encryption`/`use-compression` on **no** command — its
/// pflag names are `uc`/`ue` (measured on the v0.71.0 binary) — so the older
/// names are frp-rs extensions, accepted so existing command lines keep
/// working. This test is what holds the alias half of that decision: a later
/// edit that dropped an alias would otherwise leave the whole suite green.
///
/// Both frp-rs spellings are parsed **per surface** here, hyphen included:
/// `GO_BOOL_SITES` carries only the underscore form on `frpc tcp`, so leaving
/// `--use-compression` to that table would let any surface drop the hyphen
/// alias with the whole suite still green.
#[test]
fn every_proxy_surface_accepts_go_bool_names_and_their_frp_rs_aliases() {
    const SURFACES: [(&str, &[&str]); 8] = [
        ("tcp", &["--local-port", "1", "--remote-port", "2"]),
        ("udp", &["--local-port", "1", "--remote-port", "2"]),
        (
            "http",
            &["--local-port", "1", "--custom-domain", "h.example"],
        ),
        (
            "https",
            &["--local-port", "1", "--custom-domain", "h.example"],
        ),
        ("stcp", &["--local-port", "1", "--sk", "s"]),
        ("xtcp", &["--local-port", "1", "--sk", "s"]),
        ("sudp", &["--local-port", "1", "--remote-port", "1"]),
        ("tcpmux", &["--local-port", "1"]),
    ];
    // `(argv spelling, read the encryption field, read the compression field)`
    let read = |command: &FrpcCmd| -> (bool, bool) {
        match command {
            FrpcCmd::Tcp(a) => (a.use_encryption, a.use_compression),
            FrpcCmd::Udp(a) => (a.use_encryption, a.use_compression),
            FrpcCmd::Http(a) => (a.use_encryption, a.use_compression),
            FrpcCmd::Https(a) => (a.use_encryption, a.use_compression),
            FrpcCmd::Stcp(a) => (a.use_encryption, a.use_compression),
            FrpcCmd::Xtcp(a) => (a.use_encryption, a.use_compression),
            FrpcCmd::Sudp(a) => (a.use_encryption, a.use_compression),
            FrpcCmd::Tcpmux(a) => (a.use_encryption, a.use_compression),
            other => panic!("expected a proxy command, got {other:?}"),
        }
    };
    for (surface, required) in SURFACES {
        let mut base: Vec<&str> = vec![surface];
        base.extend_from_slice(required);
        for (flag, expect_encryption) in [
            ("--ue", true),
            ("--use-encryption", true),
            ("--use_encryption", true),
            ("--uc", false),
            ("--use-compression", false),
            ("--use_compression", false),
        ] {
            let mut argv = base.clone();
            argv.push(flag);
            let command =
                parse_frpc_proxy(&argv).unwrap_or_else(|e| panic!("frpc {surface} {flag}: {e:?}"));
            let (encryption, compression) = read(&command);
            assert_eq!(
                encryption, expect_encryption,
                "frpc {surface} {flag} must set use_encryption={expect_encryption}"
            );
            assert_eq!(
                compression, !expect_encryption,
                "frpc {surface} {flag} must only set its own field"
            );
        }
    }
}

/// Every proxy surface accepts each alias the row list declares for it.
///
/// The alias column of `proxy_flag_specs` is invisible to `--help` — aliases
/// never render — so before this test only the `go_bool` rows had a runtime
/// witness ([`every_proxy_surface_accepts_go_bool_names_and_their_frp_rs_aliases`]).
/// The adversarial review of #656 measured that deleting `"http_user"` from
/// the http row, or `"remote_port"` from the tcp row, left **both** suites and
/// every `--help` pin green while silently refusing command lines that used to
/// parse. This table is that column transcribed: one entry per `(surface,
/// canonical long, alias)`, so a dropped alias reds a named assertion instead
/// of vanishing.
///
/// The five common rows' aliases are declared on all eight surfaces, so they
/// are applied to every surface here and stated once; the per-surface tails
/// are listed per surface. `go_bool` rows are excluded because the test above
/// already walks them by argv.
#[test]
fn every_proxy_surface_accepts_the_aliases_its_rows_declare() {
    /// `(long, alias)` for the eight fields every proxy command declares.
    const COMMON: [(&str, &str); 5] = [
        ("local-ip", "local_ip"),
        ("local-port", "local_port"),
        ("proxy-name", "proxy_name"),
        ("server-addr", "server_addr"),
        ("server-port", "server_port"),
    ];
    /// `(surface, [(long, alias)])` for the rows only that surface declares.
    const PER_SURFACE: [(&str, &[(&str, &str)]); 8] = [
        ("tcp", &[("remote-port", "remote_port")]),
        ("udp", &[("remote-port", "remote_port")]),
        (
            "http",
            &[
                ("custom-domain", "custom-domains"),
                ("custom-domain", "custom_domain"),
                ("host-header-rewrite", "host_header_rewrite"),
                ("http-pwd", "http_pwd"),
                ("http-user", "http_user"),
                ("sd", "subdomain"),
            ],
        ),
        (
            "https",
            &[
                ("custom-domain", "custom-domains"),
                ("custom-domain", "custom_domain"),
                ("sd", "subdomain"),
            ],
        ),
        (
            "stcp",
            &[
                ("tls-server-name", "server-name"),
                ("tls-server-name", "server_name"),
            ],
        ),
        (
            "xtcp",
            &[
                ("tls-server-name", "server-name"),
                ("tls-server-name", "server_name"),
            ],
        ),
        ("sudp", &[("remote-port", "remote_port")]),
        (
            "tcpmux",
            &[
                ("custom-domain", "custom-domains"),
                ("custom-domain", "custom_domain"),
                ("sd", "subdomain"),
            ],
        ),
    ];
    fn value(long: &str) -> &'static str {
        match long {
            "custom-domain" => "h.example",
            "host-header-rewrite" => "h",
            "http-pwd" => "p",
            "http-user" => "u",
            "local-ip" => "10.0.0.1",
            "local-port" => "1",
            "proxy-name" => "p",
            "remote-port" => "2",
            "sd" => "sub",
            "server-addr" => "10.0.0.2",
            "server-port" => "7001",
            "tls-server-name" => "n",
            other => panic!("no sample value for the proxy row `{other}`"),
        }
    }
    for (surface, extras) in PER_SURFACE {
        let required: &[&str] = match surface {
            "tcp" => &["--local-port", "1", "--remote-port", "2"],
            "udp" => &["--local-port", "1", "--remote-port", "2"],
            "http" => &["--local-port", "1", "--custom-domain", "h.example"],
            "https" => &["--local-port", "1", "--custom-domain", "h.example"],
            "stcp" | "xtcp" => &["--local-port", "1", "--sk", "s"],
            "sudp" => &["--local-port", "1", "--remote-port", "1"],
            "tcpmux" => &["--local-port", "1"],
            other => panic!("no minimal argv for `{other}`"),
        };
        let aliases = COMMON.iter().copied().chain(extras.iter().copied());
        for (long, alias) in aliases {
            let canonical = format!("--{long}");
            let spelling = format!("--{alias}");
            let mut argv: Vec<String> = vec![surface.to_string()];
            let mut substituted = false;
            for arg in required {
                if *arg == canonical {
                    argv.push(spelling.clone());
                    substituted = true;
                } else {
                    argv.push((*arg).to_string());
                }
            }
            if !substituted {
                argv.push(spelling.clone());
                argv.push(value(long).to_string());
            }
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            parse_frpc_proxy(&refs).unwrap_or_else(|e| {
                panic!(
                    "`{spelling}` is the alias `proxy_flag_specs` declares for `--{long}` \
                     on `frpc {surface}`, but `{}` was refused: {e:?}",
                    refs.join(" ")
                )
            });
        }
    }
}

/// Each proxy row's `fallback:` cell matches the default its own usage prints.
///
/// The two live in different places — the fallback in `proxy_flag_specs`, the
/// `(default …)` text in the `FRPC_PROXY_GO_FLAGS` row that renders — so a row
/// can dial one port while its help claims another. Changing
/// `server_port`'s `fallback: 7000` to `7001` was measured to leave every test
/// and every `--help` pin green: a correct-looking document from a wrong row
/// list. This is the "one statement, two derivations" check for that cell.
#[test]
fn every_proxy_row_fallback_matches_the_default_its_usage_prints() {
    fn printed_default(long: &str) -> String {
        let row = FRPC_PROXY_GO_FLAGS
            .iter()
            .find(|row| row.long == long)
            .unwrap_or_else(|| panic!("no Go row for `{long}`"));
        let start = row
            .usage
            .find("(default ")
            .unwrap_or_else(|| panic!("`{long}`'s usage prints no default: {:?}", row.usage))
            + "(default ".len();
        let rest = &row.usage[start..];
        let end = rest
            .find(')')
            .unwrap_or_else(|| panic!("`{long}`'s default is unterminated: {:?}", row.usage));
        rest[..end].trim_matches('"').to_string()
    }
    const SURFACES: [(&str, &[&str]); 8] = [
        ("tcp", &["--local-port", "1", "--remote-port", "2"]),
        ("udp", &["--local-port", "1", "--remote-port", "2"]),
        (
            "http",
            &["--local-port", "1", "--custom-domain", "h.example"],
        ),
        (
            "https",
            &["--local-port", "1", "--custom-domain", "h.example"],
        ),
        ("stcp", &["--local-port", "1", "--sk", "s"]),
        ("xtcp", &["--local-port", "1", "--sk", "s"]),
        ("sudp", &["--local-port", "1", "--remote-port", "1"]),
        ("tcpmux", &["--local-port", "1"]),
    ];
    for (surface, required) in SURFACES {
        let mut argv: Vec<&str> = vec![surface];
        argv.extend_from_slice(required);
        let command = parse_frpc_proxy(&argv).unwrap_or_else(|e| panic!("frpc {surface}: {e:?}"));
        let (local_ip, server_addr, server_port) = match &command {
            FrpcCmd::Tcp(a) => (a.local_ip.clone(), a.server_addr.clone(), a.server_port),
            FrpcCmd::Udp(a) => (a.local_ip.clone(), a.server_addr.clone(), a.server_port),
            FrpcCmd::Http(a) => (a.local_ip.clone(), a.server_addr.clone(), a.server_port),
            FrpcCmd::Https(a) => (a.local_ip.clone(), a.server_addr.clone(), a.server_port),
            FrpcCmd::Stcp(a) => (a.local_ip.clone(), a.server_addr.clone(), a.server_port),
            FrpcCmd::Xtcp(a) => (a.local_ip.clone(), a.server_addr.clone(), a.server_port),
            FrpcCmd::Sudp(a) => (a.local_ip.clone(), a.server_addr.clone(), a.server_port),
            FrpcCmd::Tcpmux(a) => (a.local_ip.clone(), a.server_addr.clone(), a.server_port),
            other => panic!("expected a proxy command, got {other:?}"),
        };
        assert_eq!(
            local_ip,
            printed_default("local-ip"),
            "frpc {surface}: the `local_ip` fallback disagrees with the default \
             `--local-ip` prints"
        );
        assert_eq!(
            server_addr,
            printed_default("server-addr"),
            "frpc {surface}: the `server_addr` fallback disagrees with the default \
             `--server-addr` prints"
        );
        assert_eq!(
            server_port.to_string(),
            printed_default("server-port"),
            "frpc {surface}: the `server_port` fallback disagrees with the default \
             `--server-port` prints"
        );
    }
}

/// Each surface's `to_proxy_config` maps the flags it parsed where they belong.
///
/// The exhaustive destructure in each builder makes the compiler ask for a
/// destination; it cannot ask whether the destination is *right*. The
/// adversarial review of #657 measured that by mutating one mapping at a time:
/// `proxy_type` swapped wrong, `remote_port` zeroed, `sk` dropped, the
/// `httpconnect` default dropped, `locations` emptied, `local_ip` emptied —
/// sixteen such mutations left every test green, because nothing asserted the
/// built config at all. This test is that assertion: one command line per
/// surface with distinctive values, then the fields that line names.
#[test]
fn every_proxy_surface_builds_the_config_its_flags_describe() {
    fn built(argv: &[&str]) -> crate::config::ProxyConfig {
        let command =
            parse_frpc_proxy(argv).unwrap_or_else(|e| panic!("{}: {e:?}", argv.join(" ")));
        match &command {
            FrpcCmd::Tcp(a) => a.to_proxy_config(),
            FrpcCmd::Udp(a) => a.to_proxy_config(),
            FrpcCmd::Http(a) => a.to_proxy_config(),
            FrpcCmd::Https(a) => a.to_proxy_config(),
            FrpcCmd::Stcp(a) => a.to_proxy_config(),
            FrpcCmd::Xtcp(a) => a.to_proxy_config(),
            FrpcCmd::Sudp(a) => a.to_proxy_config(),
            FrpcCmd::Tcpmux(a) => a.to_proxy_config(),
            other => panic!("expected a proxy command, got {other:?}"),
        }
    }
    const WRAPPED: [&str; 4] = ["--ue", "--uc", "--server-addr", "10.9.9.9"];

    for proxy_type in ["tcp", "udp"] {
        let mut argv = vec![proxy_type, "--local-port", "4321", "--remote-port", "4322"];
        argv.extend_from_slice(&WRAPPED);
        let config = built(&argv);
        assert_eq!(config.proxy_type, proxy_type);
        assert_eq!(config.name, format!("{proxy_type}-4321->4322"));
        assert_eq!(config.local_ip, "127.0.0.1", "{proxy_type}: local_ip");
        assert_eq!(config.local_port, 4321, "{proxy_type}: local_port");
        assert_eq!(config.remote_port, 4322, "{proxy_type}: remote_port");
        assert!(config.use_encryption, "{proxy_type}: --ue");
        assert!(config.use_compression, "{proxy_type}: --uc");
    }

    let http = built(&[
        "http",
        "--local-port",
        "4321",
        "--custom-domain",
        "a.example, b.example",
        "--sd",
        "sub",
        "--locations",
        "/one, /two",
        "--http-user",
        "u",
        "--http-pwd",
        "p",
        "--host-header-rewrite",
        "h",
    ]);
    assert_eq!(http.proxy_type, "http");
    assert_eq!(http.name, "http-4321");
    assert_eq!(http.custom_domains, ["a.example", "b.example"]);
    assert_eq!(http.subdomain, "sub");
    assert_eq!(http.locations, ["/one", "/two"]);
    assert_eq!(http.http_user, "u");
    assert_eq!(http.http_pwd, "p");
    assert_eq!(http.host_header_rewrite, "h");

    let https = built(&[
        "https",
        "--local-port",
        "4321",
        "--custom-domain",
        "a.example,b.example",
        "--sd",
        "sub",
    ]);
    assert_eq!(https.proxy_type, "https");
    assert_eq!(https.name, "https-4321");
    assert_eq!(https.custom_domains, ["a.example", "b.example"]);
    assert_eq!(https.subdomain, "sub");

    for proxy_type in ["stcp", "xtcp"] {
        let named = built(&[
            proxy_type,
            "--local-port",
            "4321",
            "--sk",
            "SECRET",
            "--proxy-name",
            "given",
        ]);
        assert_eq!(named.proxy_type, proxy_type);
        assert_eq!(named.name, "given", "{proxy_type}: --proxy-name wins");
        assert_eq!(named.sk, "SECRET", "{proxy_type}: --sk");
        // Recorded frp-rs quirk: with no `--proxy-name`, stcp/xtcp derive the
        // proxy name from `--tls-server-name`, which is Go's visitor-side TLS
        // name and not a proxy name at all (`docs/developing.md`).
        let unnamed = built(&[proxy_type, "--local-port", "4321", "--sk", "S"]);
        assert_eq!(unnamed.name, format!("{proxy_type}-proxy"));
        let from_server_name = built(&[
            proxy_type,
            "--local-port",
            "4321",
            "--sk",
            "S",
            "--tls-server-name",
            "tls.example",
        ]);
        assert_eq!(
            from_server_name.name, "tls.example",
            "{proxy_type}: --tls-server-name is the fallback the code documents"
        );
    }

    let sudp = built(&[
        "sudp",
        "--local-port",
        "4321",
        "--remote-port",
        "4322",
        "--sk",
        "SECRET",
    ]);
    assert_eq!(sudp.proxy_type, "sudp");
    assert_eq!(sudp.name, "sudp-4321->4322");
    assert_eq!(sudp.remote_port, 4322);
    assert_eq!(sudp.sk, "SECRET");

    let tcpmux = built(&["tcpmux", "--local-port", "4321", "--mux-port", "4322"]);
    assert_eq!(tcpmux.proxy_type, "tcpmux");
    assert_eq!(tcpmux.name, "tcpmux-4321");
    assert_eq!(tcpmux.remote_port, 4322, "--mux-port becomes remote_port");
    assert_eq!(tcpmux.multiplexer, "httpconnect", "the documented default");
    let explicit = built(&[
        "tcpmux",
        "--local-port",
        "4321",
        "--mux-port",
        "4322",
        "--mux",
        "http2",
        "--custom-domain",
        "a.example,b.example",
        "--sd",
        "sub",
    ]);
    assert_eq!(explicit.multiplexer, "http2");
    assert_eq!(explicit.custom_domains, ["a.example", "b.example"]);
    assert_eq!(explicit.subdomain, "sub");
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
fn allow_unsafe_appends_and_comma_splits_on_every_reading_surface() {
    // pflag's `strings` value **appends** on repetition — it is not
    // last-wins — and Go comma-splits every occurrence. Measured on v0.71.0:
    // `frps verify`/`frpc verify` exit 0 for both value orders (and for
    // `Ignored,TokenSourceExec`), because any occurrence that enables
    // `TokenSourceExec` is enough. A last-wins reading would let a later
    // unrelated value cancel an earlier enabling one and so refuse a config
    // Go accepts, which is exactly the regression this pins.
    let verify = parse_frpc_verify(&[
        "verify",
        "-c",
        "p7520.toml",
        "--allow-unsafe",
        "WrongFeature",
        "--allow-unsafe",
        "Ignored,TokenSourceExec",
    ])
    .unwrap();
    assert_eq!(
        verify.allow_unsafe,
        ["WrongFeature", "Ignored", "TokenSourceExec"].map(String::from),
        "a repeated `--allow-unsafe` must append in order and comma-split each occurrence"
    );

    // Three occurrences, with the enabling value **last**. Every earlier pin
    // fed at most two occurrences, so a parser that capped the accumulation
    // at two stayed green while the shared parser regressed — measured: with
    // `.many().map(|mut v: Vec<String>| { v.truncate(2); v })` the gate
    // refused this row (rc 1) where the head and Go v0.71.0 are rc 0. The
    // full ordered vector is asserted, so truncation anywhere shows up here.
    let three = parse_frpc_verify(&[
        "verify",
        "-c",
        "p7520.toml",
        "--allow-unsafe",
        "WrongFeature",
        "--allow-unsafe",
        "Ignored",
        "--allow-unsafe",
        "TokenSourceExec",
    ])
    .unwrap();
    assert_eq!(
        three.allow_unsafe,
        ["WrongFeature", "Ignored", "TokenSourceExec"].map(String::from),
        "three occurrences must accumulate in order — capping at two drops the enabling value"
    );

    // Four occurrences, enabling value last: the next step out. Measured on
    // Go v0.71.0, four *and* five occurrences are each rc 0 on `frps verify`
    // and `frpc verify` — pflag's `strings` value has no cap at all — so a
    // literal row here buys one step rather than the class.
    let four = parse_frpc_verify(&[
        "verify",
        "-c",
        "p7520.toml",
        "--allow-unsafe",
        "A",
        "--allow-unsafe",
        "B",
        "--allow-unsafe",
        "Cc",
        "--allow-unsafe",
        "TokenSourceExec",
    ])
    .unwrap();
    assert_eq!(
        four.allow_unsafe,
        ["A", "B", "Cc", "TokenSourceExec"].map(String::from),
        "four occurrences must accumulate in order — capping at three drops the enabling value"
    );

    // The class itself: the accumulation is unbounded, so assert a wide
    // occurrence list instead of chasing the next `truncate(n)` one step at a
    // time. Any cap of at most 31 dies here; the literal rows above and the
    // two spawn pins keep the process-level rows honest (a spawn pin cannot
    // generate argv).
    let wide_n: usize = 32;
    let mut wide_argv = vec![
        "verify".to_string(),
        "-c".to_string(),
        "p7520.toml".to_string(),
    ];
    let mut wide_expected: Vec<String> = (0..wide_n - 1).map(|i| format!("Filler{i}")).collect();
    for value in &wide_expected {
        wide_argv.push("--allow-unsafe".to_string());
        wide_argv.push(value.clone());
    }
    wide_expected.push("TokenSourceExec".to_string());
    wide_argv.push("--allow-unsafe".to_string());
    wide_argv.push("TokenSourceExec".to_string());
    let wide =
        parse_frpc_verify(&wide_argv.iter().map(String::as_str).collect::<Vec<&str>>()).unwrap();
    assert_eq!(
        wide.allow_unsafe, wide_expected,
        "the occurrence list is unbounded — any cap of at most {wide_n} occurrences drops the \
         trailing enabling value"
    );

    let frps_verify = parse_frps_verify(&[
        "verify",
        "-c",
        "p7520.toml",
        "--allow-unsafe",
        "TokenSourceExec",
        "--allow-unsafe",
        "WrongFeature",
    ])
    .unwrap();
    assert_eq!(
        frps_verify.allow_unsafe,
        ["TokenSourceExec", "WrongFeature"].map(String::from),
        "the frps verify surface reads the same value and must append too"
    );

    // Both run paths read the value as well (the construction gate consumes
    // it), and Go accepts the repetition there: measured, `frps -c <exec
    // cfg> --allow-unsafe WrongFeature --allow-unsafe TokenSourceExec`
    // starts and logs its listener.
    let run = parse_frpc_run(&[
        "-c",
        "p7520.toml",
        "--allow-unsafe",
        "WrongFeature",
        "--allow-unsafe",
        "TokenSourceExec",
    ])
    .unwrap();
    assert_eq!(
        run.allow_unsafe,
        ["WrongFeature", "TokenSourceExec"].map(String::from)
    );
    // Three occurrences in the wrong order on the frps run path too: every
    // value survives, so an accumulation cap cannot hide here either.
    let frps_run = parse_frps(&[
        "-c",
        "p7520.toml",
        "--allow-unsafe",
        "TokenSourceExec",
        "--allow-unsafe",
        "Ignored",
        "--allow-unsafe",
        "WrongFeature",
    ])
    .unwrap();
    assert_eq!(
        frps_run.allow_unsafe,
        ["TokenSourceExec", "Ignored", "WrongFeature"].map(String::from),
        "a wrong-order three-occurrence run path keeps every value as well"
    );

    // The same value twice must survive **as two**. Every pin above feeds
    // distinct values, so a de-dup or last-wins reading stayed green —
    // measured, an accumulation that keeps only the last occurrence left
    // the whole frp-core lib suite green before this row existed.
    let repeated = parse_frpc_verify(&[
        "verify",
        "-c",
        "p7520.toml",
        "--allow-unsafe",
        "TokenSourceExec",
        "--allow-unsafe",
        "TokenSourceExec",
    ])
    .unwrap();
    assert_eq!(
        repeated.allow_unsafe,
        ["TokenSourceExec", "TokenSourceExec"].map(String::from),
        "an identical value repeated must be kept twice, not de-duplicated"
    );
    assert_eq!(
        read_ignored_allow_unsafe(&["--allow-unsafe", "Same", "--allow-unsafe", "Same"]).unwrap(),
        ["Same", "Same"].map(String::from),
        "the ignored twin de-duplicates nothing either"
    );

    // The class past any plausible cap, at both accumulation sites: 40
    // occurrences, and 40 CSV elements inside one occurrence. Measured
    // before these rows, a cap of 32 at either site (`v.truncate(32)` on the
    // accumulated vector, `split(',').take(32)` in the reader) left the whole
    // frp-core lib suite green — the widest row held exactly 32 values.
    let wide_n: usize = 40;
    let mut many_argv = vec![
        "verify".to_string(),
        "-c".to_string(),
        "p7520.toml".to_string(),
    ];
    let mut many_expected: Vec<String> = Vec::new();
    for i in 0..wide_n - 1 {
        let value = format!("Filler{i}");
        many_argv.push("--allow-unsafe".to_string());
        many_argv.push(value.clone());
        many_expected.push(value);
    }
    many_expected.push("TokenSourceExec".to_string());
    many_argv.push("--allow-unsafe".to_string());
    many_argv.push("TokenSourceExec".to_string());
    let many =
        parse_frpc_verify(&many_argv.iter().map(String::as_str).collect::<Vec<&str>>()).unwrap();
    assert_eq!(
        many.allow_unsafe, many_expected,
        "the occurrence list is unbounded — a cap of at most {wide_n} occurrences drops the \
         trailing enabling value"
    );

    let elements: Vec<String> = (0..wide_n - 1).map(|i| format!("Filler{i}")).collect();
    let csv_value = format!("{},TokenSourceExec", elements.join(","));
    let mut csv_expected = elements;
    csv_expected.push("TokenSourceExec".to_string());
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", &csv_value]).unwrap(),
        csv_expected,
        "the CSV element list is unbounded — a cap of at most {wide_n} elements drops the \
         trailing enabling value"
    );
    assert_eq!(
        read_ignored_allow_unsafe(&["--allow-unsafe", &csv_value]).unwrap(),
        csv_expected,
        "the ignored twin reads the same unbounded element list"
    );
}

#[test]
fn allow_unsafe_reads_pflags_csv_record_on_both_parsers() {
    // pflag registers the flag as `StringSliceVarP` (frpc
    // `cmd/frpc/sub/root.go:55`, frps `cmd/frps/root.go:47`) and reads a
    // `strings` value through Go's `encoding/csv` (`LazyQuotes=false`,
    // `TrimLeadingSpace=false`), reading one record. Measured on Go v0.71.0
    // with `frpc verify -c <exec tokenSource cfg> --allow-unsafe <value>`:
    //   `"TokenSourceExec"`       rc 0 (matched quotes stripped)
    //   `A, TokenSourceExec`      rc 1 (leading space kept, so no match)
    //   `TokenSourceExec`         rc 0
    //   `Ignored,TokenSourceExec` rc 0
    //   (no flag)                 rc 1
    // The head read the value with `split(',').map(trim)`, so it accepted a
    // spaced element Go refuses and refused the quoted spelling Go accepts.
    let rows: [(&str, &[&str]); 4] = [
        ("\"TokenSourceExec\"", &["TokenSourceExec"]),
        ("A, TokenSourceExec", &["A", " TokenSourceExec"]),
        ("TokenSourceExec", &["TokenSourceExec"]),
        ("Ignored,TokenSourceExec", &["Ignored", "TokenSourceExec"]),
    ];
    for (value, expected) in rows {
        let expected: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", value]).unwrap(),
            expected,
            "allow_unsafe_parser must read `{value}` the way pflag's CSV reader does"
        );
        assert_eq!(
            read_ignored_allow_unsafe(&["--allow-unsafe", value]).unwrap(),
            expected,
            "the ignored twin must read `{value}` identically (Go parses the persistent flag \
             for every subcommand)"
        );
    }
    // The fifth row: with no flag both parsers yield no features.
    assert!(read_allow_unsafe(&[]).unwrap().is_empty());
    assert!(read_ignored_allow_unsafe(&[]).unwrap().is_empty());
}

#[test]
fn allow_unsafe_csv_corners_are_go_shaped_and_never_trimmed() {
    // Quote corners, measured on Go v0.71.0 (all rc 0):
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", "\"a\"\"b\",TokenSourceExec"]).unwrap(),
        ["a\"b", "TokenSourceExec"],
        "a doubled quote inside a quoted element is one literal quote"
    );
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", "\"a,b\",TokenSourceExec"]).unwrap(),
        ["a,b", "TokenSourceExec"],
        "a comma inside quotes is data, not an element boundary"
    );
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", "\"\",TokenSourceExec"]).unwrap(),
        ["", "TokenSourceExec"],
        "an empty quoted element is an empty value, not an absent one"
    );
    // Empty elements are kept and whitespace is never trimmed. Measured:
    // `a,,b` parses as `a`, ``, `b` (Go rc 0 for `a,,TokenSourceExec`),
    // while ` TokenSourceExec`, `TokenSourceExec `, `A,\tTokenSourceExec`
    // and `'TokenSourceExec'` are all rc 1 — the head's `trim()` made the
    // first three rc 0.
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", "a,,b"]).unwrap(),
        ["a", "", "b"]
    );
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", " TokenSourceExec "]).unwrap(),
        [" TokenSourceExec "]
    );
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", "A,\tTokenSourceExec"]).unwrap(),
        ["A", "\tTokenSourceExec"]
    );
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", "'TokenSourceExec'"]).unwrap(),
        ["'TokenSourceExec'"],
        "single quotes are data — pflag only strips matched double quotes"
    );
    // A trailing CR is the line terminator, not data (Go rc 0 for
    // `TokenSourceExec\r`); a CR anywhere else is data (Go rc 1).
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", "TokenSourceExec\r"]).unwrap(),
        ["TokenSourceExec"]
    );
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", "\rTokenSourceExec"]).unwrap(),
        ["\rTokenSourceExec"]
    );
    // Only the first record is read: measured, `"TokenSourceExec"\njunk` is
    // rc 0 in Go — the second record is never parsed, malformed or not
    // (`A\n"unclosed` is the *gate* line, not a pflag parse error).
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", "\"TokenSourceExec\"\njunk"]).unwrap(),
        ["TokenSourceExec"]
    );
    // A record pflag refuses is refused here too, on both parsers, because
    // Go parses the persistent flag for every subcommand: measured, `frpc
    // tcp|status|reload -c <cfg> --allow-unsafe '"abc'` is rc 1 with
    // `Error: invalid argument "\"abc" for "--allow-unsafe" flag: parse
    // error on line 1, column 5: extraneous or missing " in quoted-field`.
    for bad in [
        "\"abc",
        "a\"b",
        "\"TokenSourceExec\"x",
        "\"TokenSourceExec\" ",
    ] {
        assert!(
            read_allow_unsafe(&["--allow-unsafe", bad]).is_err(),
            "allow_unsafe_parser must refuse `{bad}`"
        );
        assert!(
            read_ignored_allow_unsafe(&["--allow-unsafe", bad]).is_err(),
            "the ignored twin must refuse `{bad}` too"
        );
    }
}

#[test]
fn allow_unsafe_skips_blank_lines_like_go_and_blank_only_is_an_eof_flag_error() {
    // Go's `encoding/csv` `readRecord` skips blank lines while reading a
    // record (`$GOROOT/src/encoding/csv/reader.go`), so a value that starts
    // with one still parses — measured on Go v0.71.0, `frpc verify -c <exec
    // cfg> --allow-unsafe $'\nTokenSourceExec'` is rc 0 while the head was
    // rc 1 (its reader never skipped the blank).
    for value in [
        "\nTokenSourceExec",
        "\n\nTokenSourceExec",
        "\r\nTokenSourceExec",
    ] {
        let expected = vec!["TokenSourceExec".to_string()];
        assert_eq!(
            read_allow_unsafe(&["--allow-unsafe", value]).unwrap(),
            expected,
            "leading blank lines must be skipped for {value:?}"
        );
        assert_eq!(
            read_ignored_allow_unsafe(&["--allow-unsafe", value]).unwrap(),
            expected,
            "the ignored twin must skip leading blank lines for {value:?}"
        );
    }
    // A blank line *inside* a quoted field is data, not a separator
    // (measured: `"a\n\nb"` is rc 1 with the gate line, not a parse error).
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", "\"a\n\nb\""]).unwrap(),
        ["a\n\nb"]
    );
    // A value that is nothing but blank lines leaves Go's reader with no
    // record at all: `readRecord` returns `io.EOF`, which pflag reports as
    // `invalid argument "\n" for "--allow-unsafe" flag: EOF` (measured, rc 1
    // on stderr — not the `unsafe feature …` gate line).
    for value in ["\n", "\r\n", "\n\n", "\r"] {
        assert_eq!(
            split_allow_unsafe_csv(value),
            Err("EOF".to_string()),
            "the reader must return Go's io.EOF for the blank-only value {value:?}"
        );
        for (label, parsed) in [
            (
                "allow_unsafe_parser",
                read_allow_unsafe(&["--allow-unsafe", value]),
            ),
            (
                "ignored twin",
                read_ignored_allow_unsafe(&["--allow-unsafe", value]),
            ),
        ] {
            let failure = parsed.expect_err(&format!("{label} must refuse {value:?}"));
            let rendered = failure.unwrap_stderr();
            assert!(
                rendered.contains(": EOF"),
                "{label} must report Go's EOF for {value:?}, got: {rendered}"
            );
        }
    }
    // The flip side of skipping blanks: the first record's terminator ends
    // the read, so a later malformed record is never parsed (measured: Go is
    // rc 1 on the gate line for `A\n"unclosed`).
    assert_eq!(
        read_allow_unsafe(&["--allow-unsafe", "A\n\"unclosed"]).unwrap(),
        ["A"]
    );
    assert_eq!(
        read_ignored_allow_unsafe(&["--allow-unsafe", "A\n\"unclosed"]).unwrap(),
        ["A"]
    );
}

#[test]
fn allow_unsafe_error_positions_are_go_lines_and_byte_columns() {
    // Go's `encoding/csv` `ParseError` counts 1-based **byte** columns on
    // 1-based lines, and prefixes `record on line N; ` when the error sits
    // on a later line than the record started on
    // (`$GOROOT/src/encoding/csv/reader.go`). Every row was measured on Go
    // v0.71.0 with `frpc verify` and `frps verify` (byte-identical); only
    // the `parse error …` tail is pinned, not frp-rs's surrounding sentence.
    let rows: [(&str, &str); 11] = [
        // The ASCII rows of the PR table keep their columns.
        (
            "\"abc",
            "parse error on line 1, column 5: extraneous or missing \" in quoted-field",
        ),
        (
            "\"TokenSourceExec\"x",
            "parse error on line 1, column 17: extraneous or missing \" in quoted-field",
        ),
        (
            "a\"b",
            "parse error on line 1, column 2: bare \" in non-quoted-field",
        ),
        // Multi-byte input: the column is bytes, not runes.
        (
            "\"é",
            "parse error on line 1, column 4: extraneous or missing \" in quoted-field",
        ),
        (
            "é\"x",
            "parse error on line 1, column 3: bare \" in non-quoted-field",
        ),
        (
            "x,é\"y",
            "parse error on line 1, column 5: bare \" in non-quoted-field",
        ),
        (
            "\"abc\r",
            "parse error on line 1, column 5: extraneous or missing \" in quoted-field",
        ),
        (
            "\"\"\"",
            "parse error on line 1, column 4: extraneous or missing \" in quoted-field",
        ),
        // A quoted field may span lines: the reported line advances and the
        // `record on line N; ` prefix appears.
        (
            "\"a\nbc\"x",
            "record on line 1; parse error on line 2, column 3: extraneous or missing \" in \
             quoted-field",
        ),
        (
            "\"a\nb",
            "record on line 1; parse error on line 2, column 2: extraneous or missing \" in \
             quoted-field",
        ),
        // The record itself starts on line 2 after the skipped blank, so
        // there is no prefix (the record line is the error line).
        (
            "\n\"a",
            "parse error on line 2, column 3: extraneous or missing \" in quoted-field",
        ),
    ];
    for (value, expected) in rows {
        // The reader's own message is Go's `ParseError` text exactly.
        assert_eq!(
            split_allow_unsafe_csv(value),
            Err(expected.to_string()),
            "the reader must place {value:?} at `{expected}`"
        );
        // And both parser surfaces must refuse it, since Go parses the
        // persistent flag for every subcommand.
        for (label, parsed) in [
            (
                "allow_unsafe_parser",
                read_allow_unsafe(&["--allow-unsafe", value]),
            ),
            (
                "ignored twin",
                read_ignored_allow_unsafe(&["--allow-unsafe", value]),
            ),
        ] {
            let failure = parsed.expect_err(&format!("{label} must refuse {value:?}"));
            // bpaf re-wraps the sentence when it renders it, so compare it
            // with whitespace collapsed.
            let rendered = failure.unwrap_stderr();
            let collapsed = rendered.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                collapsed.contains(expected),
                "{label} must relay `{expected}` for {value:?}, got: {rendered}"
            );
        }
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
        .run_inner(&prepared_cli_argv(&argv, RootCommand::Frps)[..])
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
            .run_inner(&prepared_cli_argv(&argv, RootCommand::Frps)[..])
            .unwrap_or_else(|err| panic!("frps {argv:?} must parse after the rewrite: {err:?}"));
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
        .run_inner(&prepared_cli_argv(&argv, RootCommand::Frps)[..])
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
/// Batch H1, **Item A**: Go frp v0.71.0's proxy flag *names* must be accepted,
/// and the frp-rs spellings they replace must keep parsing to the same field.
///
/// Every probe drives the real parser, so a rename that only moved the
/// rendered document (the `FRPC_*_DOC` whole-text pins) reds here too. Each
/// `--custom-domain`/`--sd`/`--tls-server-name`/`--mux` value is deliberately
/// distinct from the legacy one so a probe cannot pass by aliasing the wrong
/// field.
#[test]
fn proxy_commands_accept_go_flag_names() {
    // http: `-d, --custom-domain strings` and `--sd string`.
    let FrpcCmd::Http(http) = parse_frpc_proxy(&[
        "http",
        "-l",
        "80",
        "--custom-domain",
        "go.example",
        "--sd",
        "go-sub",
    ])
    .expect("--custom-domain / --sd must parse on frpc http") else {
        panic!("expected the http command");
    };
    assert_eq!(http.custom_domains.as_str(), "go.example");
    assert_eq!(http.subdomain.as_deref(), Some("go-sub"));
    // The three legacy spellings are hidden aliases of the same fields.
    for argv in [
        &[
            "http",
            "-l",
            "80",
            "--custom-domains",
            "old.example",
            "--subdomain",
            "old-sub",
        ][..],
        &[
            "http",
            "-l",
            "80",
            "--custom_domain",
            "old.example",
            "--subdomain",
            "old-sub",
        ][..],
    ] {
        let FrpcCmd::Http(legacy) =
            parse_frpc_proxy(argv).unwrap_or_else(|e| panic!("{argv:?} must keep parsing: {e:?}"))
        else {
            panic!("expected the http command");
        };
        assert_eq!(
            (legacy.custom_domains.as_str(), legacy.subdomain.as_deref()),
            ("old.example", Some("old-sub")),
            "{argv:?} must reach custom_domains/subdomain"
        );
    }

    // https: same two names, and `-d` is Go's shorthand.
    let FrpcCmd::Https(https) =
        parse_frpc_proxy(&["https", "-l", "443", "-d", "go.example", "--sd", "go-sub"])
            .expect("-d / --custom-domain / --sd must parse on frpc https")
    else {
        panic!("expected the https command");
    };
    assert_eq!(https.custom_domains.as_str(), "go.example");
    assert_eq!(https.subdomain.as_deref(), Some("go-sub"));

    // stcp/xtcp: `--tls-server-name string`, legacy `--server-name`/`--server_name`.
    for argv in [
        &[
            "stcp",
            "--sk",
            "s",
            "-l",
            "80",
            "--tls-server-name",
            "go.example",
        ][..],
        &[
            "xtcp",
            "--sk",
            "s",
            "-l",
            "80",
            "--tls-server-name",
            "go.example",
        ][..],
    ] {
        let (name, server_name) =
            match parse_frpc_proxy(argv).unwrap_or_else(|e| panic!("{argv:?} must parse: {e:?}")) {
                FrpcCmd::Stcp(a) => ("stcp", a.server_name),
                FrpcCmd::Xtcp(a) => ("xtcp", a.server_name),
                other => panic!("expected stcp/xtcp, got {other:?}"),
            };
        assert_eq!(
            server_name.as_deref(),
            Some("go.example"),
            "{name} --tls-server-name must reach server_name"
        );
    }
    for argv in [
        &[
            "stcp",
            "--sk",
            "s",
            "-l",
            "80",
            "--server-name",
            "old.example",
        ][..],
        &[
            "xtcp",
            "--sk",
            "s",
            "-l",
            "80",
            "--server_name",
            "old.example",
        ][..],
    ] {
        let server_name = match parse_frpc_proxy(argv)
            .unwrap_or_else(|e| panic!("{argv:?} must keep parsing: {e:?}"))
        {
            FrpcCmd::Stcp(a) => a.server_name,
            FrpcCmd::Xtcp(a) => a.server_name,
            other => panic!("expected stcp/xtcp, got {other:?}"),
        };
        assert_eq!(
            server_name.as_deref(),
            Some("old.example"),
            "{argv:?} must keep reaching server_name"
        );
    }

    // tcpmux: Go's `--mux string` is the multiplexer *name*. frp-rs's own
    // `--mux-port` (a port the tcpmux path never used) survives as an
    // extension, and is optional because Go's command line has no port flag.
    let FrpcCmd::Tcpmux(tcpmux) =
        parse_frpc_proxy(&["tcpmux", "-l", "80", "--mux", "go-mux", "--mux-port", "7"])
            .expect("--mux / --mux-port must parse on frpc tcpmux")
    else {
        panic!("expected the tcpmux command");
    };
    assert_eq!(tcpmux.mux.as_deref(), Some("go-mux"));
    assert_eq!(tcpmux.mux_port, 7);
    assert_eq!(tcpmux.to_proxy_config().multiplexer, "go-mux");
    let FrpcCmd::Tcpmux(no_port) =
        parse_frpc_proxy(&["tcpmux", "-l", "80", "--mux", "httpconnect"])
            .expect("frpc tcpmux must parse without --mux-port, which Go has no flag for")
    else {
        panic!("expected the tcpmux command");
    };
    assert_eq!(no_port.mux_port, 0);
    assert_eq!(no_port.to_proxy_config().multiplexer, "httpconnect");
    let FrpcCmd::Tcpmux(bare) =
        parse_frpc_proxy(&["tcpmux", "-l", "80"]).expect("frpc tcpmux must still parse bare")
    else {
        panic!("expected the tcpmux command");
    };
    assert_eq!(
        bare.to_proxy_config().multiplexer,
        "httpconnect",
        "a bare frpc tcpmux must keep the pre-Item-A multiplexer default"
    );

    // stcp/xtcp: Go's `-n/--proxy-name`. Round 2 added the field, so this pins
    // that it reaches both the args and the proxy's wire name; the legacy
    // `--server-name` still lands on `server_name` (the two are separate
    // fields, and `proxy_name` wins when both are given).
    for argv in [
        &["stcp", "--sk", "s", "-l", "80", "--proxy-name", "go-name"][..],
        &["xtcp", "--sk", "s", "-l", "80", "--proxy-name", "go-name"][..],
    ] {
        let (name, proxy_name) =
            match parse_frpc_proxy(argv).unwrap_or_else(|e| panic!("{argv:?} must parse: {e:?}")) {
                FrpcCmd::Stcp(a) => (a.to_proxy_config().name, a.proxy_name),
                FrpcCmd::Xtcp(a) => (a.to_proxy_config().name, a.proxy_name),
                other => panic!("expected stcp/xtcp, got {other:?}"),
            };
        assert_eq!(proxy_name.as_deref(), Some("go-name"));
        assert_eq!(name, "go-name", "{argv:?} must reach the proxy name");
    }

    // tcpmux: Go's `-d/--custom-domain strings` and `--sd string`. The comma
    // grammar is frp-rs's (Go's StringSlice takes repeats); the split must
    // reach `custom_domains` as a list.
    let FrpcCmd::Tcpmux(tcpmux_domains) = parse_frpc_proxy(&[
        "tcpmux",
        "-l",
        "80",
        "--custom-domain",
        "a.example,b.example",
        "--sd",
        "go-sub",
    ])
    .expect("--custom-domain / --sd must parse on frpc tcpmux") else {
        panic!("expected the tcpmux command");
    };
    assert_eq!(
        tcpmux_domains.custom_domains.as_deref(),
        Some("a.example,b.example")
    );
    assert_eq!(tcpmux_domains.subdomain.as_deref(), Some("go-sub"));
    let config = tcpmux_domains.to_proxy_config();
    assert_eq!(
        config.custom_domains,
        vec!["a.example".to_string(), "b.example".to_string()]
    );
    assert_eq!(config.subdomain, "go-sub");

    // sudp: Go's `--sk string`, optional like Go's (default ""). The long
    // `--remote-port` is frp-rs's own and still required; `-r` is refused.
    let FrpcCmd::Sudp(sudp) =
        parse_frpc_proxy(&["sudp", "-l", "80", "--remote-port", "1", "--sk", "go-sk"])
            .expect("--sk must parse on frpc sudp")
    else {
        panic!("expected the sudp command");
    };
    assert_eq!(sudp.sk.as_deref(), Some("go-sk"));
    assert_eq!(sudp.to_proxy_config().sk, "go-sk");
    let FrpcCmd::Sudp(no_sk) = parse_frpc_proxy(&["sudp", "-l", "80", "--remote-port", "1"])
        .expect("--sk is optional on frpc sudp, like Go")
    else {
        panic!("expected the sudp command");
    };
    assert_eq!(no_sk.sk, None);
    assert_eq!(no_sk.to_proxy_config().sk, "");
}

/// Batch H1, **Item B**: Go's proxy-command shorthands. Each `-x` must land on
/// the field its Go long flag names, on every surface Go registers it on:
/// `-i` local-ip, `-l` local-port, `-r` remote-port (tcp/udp only — Go's sudp
/// registers no `remote_port`, so frp-rs's long-only copy takes no shorthand
/// there), `-s` server-addr, `-P` server-port, `-n` proxy-name (all eight; Go
/// registers it on every proxy command), and `-d` custom-domain.
#[test]
fn proxy_command_shorthands_parse_to_their_go_long_flag() {
    let FrpcCmd::Tcp(tcp) = parse_frpc_proxy(&[
        "tcp",
        "-i",
        "10.1.2.3",
        "-l",
        "8081",
        "-r",
        "18081",
        "-s",
        "srv.example",
        "-P",
        "7001",
        "-n",
        "probe",
    ])
    .expect("-i -l -r -s -P -n must parse on frpc tcp") else {
        panic!("expected the tcp command");
    };
    assert_eq!(
        (
            tcp.local_ip.as_str(),
            tcp.local_port,
            tcp.remote_port,
            tcp.server_addr.as_str(),
            tcp.server_port,
            tcp.proxy_name.as_deref(),
        ),
        ("10.1.2.3", 8081, 18081, "srv.example", 7001, Some("probe")),
        "-i/-l/-r/-s/-P/-n must be local-ip/local-port/remote-port/server-addr/server-port/proxy-name"
    );

    let FrpcCmd::Udp(udp) = parse_frpc_proxy(&[
        "udp",
        "-i",
        "10.1.2.3",
        "-l",
        "8082",
        "-r",
        "18082",
        "-s",
        "srv.example",
        "-P",
        "7002",
        "-n",
        "probe",
    ])
    .expect("-i -l -r -s -P -n must parse on frpc udp") else {
        panic!("expected the udp command");
    };
    assert_eq!(
        (
            udp.local_ip.as_str(),
            udp.local_port,
            udp.remote_port,
            udp.server_addr.as_str(),
            udp.server_port,
            udp.proxy_name.as_deref(),
        ),
        ("10.1.2.3", 8082, 18082, "srv.example", 7002, Some("probe"))
    );

    // http/https also need their required `--custom-domain`.
    let FrpcCmd::Http(http) = parse_frpc_proxy(&[
        "http",
        "-i",
        "10.1.2.3",
        "-l",
        "8083",
        "-s",
        "srv.example",
        "-P",
        "7003",
        "-n",
        "probe",
        "-d",
        "h.example",
    ])
    .expect("-i -l -s -P -n -d must parse on frpc http") else {
        panic!("expected the http command");
    };
    assert_eq!(
        (
            http.local_ip.as_str(),
            http.local_port,
            http.server_addr.as_str(),
            http.server_port,
            http.proxy_name.as_deref(),
            http.custom_domains.as_str(),
        ),
        (
            "10.1.2.3",
            8083,
            "srv.example",
            7003,
            Some("probe"),
            "h.example"
        )
    );

    let FrpcCmd::Https(https) = parse_frpc_proxy(&[
        "https",
        "-i",
        "10.1.2.3",
        "-l",
        "8084",
        "-s",
        "srv.example",
        "-P",
        "7004",
        "-n",
        "probe",
        "-d",
        "h.example",
    ])
    .expect("-i -l -s -P -n -d must parse on frpc https") else {
        panic!("expected the https command");
    };
    assert_eq!(
        (
            https.local_ip.as_str(),
            https.local_port,
            https.server_addr.as_str(),
            https.server_port,
            https.proxy_name.as_deref(),
        ),
        ("10.1.2.3", 8084, "srv.example", 7004, Some("probe"))
    );

    let FrpcCmd::Stcp(stcp) = parse_frpc_proxy(&[
        "stcp",
        "--sk",
        "s",
        "-i",
        "10.1.2.3",
        "-l",
        "8085",
        "-s",
        "srv.example",
        "-P",
        "7005",
        "-n",
        "probe",
    ])
    .expect("-i -l -s -P -n --sk must parse on frpc stcp") else {
        panic!("expected the stcp command");
    };
    assert_eq!(
        (
            stcp.local_ip.as_str(),
            stcp.local_port,
            stcp.server_addr.as_str(),
            stcp.server_port,
            stcp.proxy_name.as_deref(),
            stcp.sk.as_str(),
        ),
        ("10.1.2.3", 8085, "srv.example", 7005, Some("probe"), "s"),
        "-n must be proxy-name and --sk must be the secret key on frpc stcp"
    );

    let FrpcCmd::Xtcp(xtcp) = parse_frpc_proxy(&[
        "xtcp",
        "--sk",
        "s",
        "-i",
        "10.1.2.3",
        "-l",
        "8086",
        "-s",
        "srv.example",
        "-P",
        "7006",
        "-n",
        "probe",
    ])
    .expect("-i -l -s -P -n --sk must parse on frpc xtcp") else {
        panic!("expected the xtcp command");
    };
    assert_eq!(
        (
            xtcp.local_ip.as_str(),
            xtcp.local_port,
            xtcp.server_addr.as_str(),
            xtcp.server_port,
            xtcp.proxy_name.as_deref(),
            xtcp.sk.as_str(),
        ),
        ("10.1.2.3", 8086, "srv.example", 7006, Some("probe"), "s")
    );

    // Sudp takes no `-r` at all: Go's sudp has no `remote_port`, and the
    // v0.71.0 binary refuses both `-r` and `--remote-port` (measured). The
    // long form is frp-rs's own, so this pins it as long-only.
    let FrpcCmd::Sudp(sudp) = parse_frpc_proxy(&[
        "sudp",
        "-i",
        "10.1.2.3",
        "-l",
        "8087",
        "--remote-port",
        "18087",
        "-s",
        "srv.example",
        "-P",
        "7007",
        "-n",
        "probe",
        "--sk",
        "s",
    ])
    .expect("-i -l -s -P -n --sk --remote-port must parse on frpc sudp") else {
        panic!("expected the sudp command");
    };
    assert_eq!(
        (
            sudp.local_ip.as_str(),
            sudp.local_port,
            sudp.remote_port,
            sudp.server_addr.as_str(),
            sudp.server_port,
            sudp.proxy_name.as_deref(),
            sudp.sk.as_deref(),
        ),
        (
            "10.1.2.3",
            8087,
            18087,
            "srv.example",
            7007,
            Some("probe"),
            Some("s")
        )
    );
    assert!(
        parse_frpc_proxy(&["sudp", "-l", "1", "-r", "18087"]).is_err(),
        "frpc sudp -r must stay refused: Go registers no remote_port there"
    );

    let FrpcCmd::Tcpmux(tcpmux) = parse_frpc_proxy(&[
        "tcpmux",
        "-i",
        "10.1.2.3",
        "-l",
        "8088",
        "-s",
        "srv.example",
        "-P",
        "7008",
        "-n",
        "probe",
        "-d",
        "t.example",
        "--sd",
        "sub",
    ])
    .expect("-i -l -s -P -n -d --sd must parse on frpc tcpmux") else {
        panic!("expected the tcpmux command");
    };
    assert_eq!(
        (
            tcpmux.local_ip.as_str(),
            tcpmux.local_port,
            tcpmux.server_addr.as_str(),
            tcpmux.server_port,
            tcpmux.proxy_name.as_deref(),
            tcpmux.custom_domains.as_deref(),
            tcpmux.subdomain.as_deref(),
        ),
        (
            "10.1.2.3",
            8088,
            "srv.example",
            7008,
            Some("probe"),
            Some("t.example"),
            Some("sub")
        )
    );
}
