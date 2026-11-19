use super::*;

fn hoist(args: &[&str]) -> Vec<String> {
    let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
    hoist_leading_subcommand(&argv, RootCommand::Frpc)
        .into_iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect()
}

fn prepared(args: &[&str]) -> Vec<String> {
    let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
    prepared_cli_argv(&argv, RootCommand::Frpc)
        .into_iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect()
}

/// The same two helpers on the **`frps`** surface. They are separate
/// functions rather than a parameter because every assertion below is about
/// one root command's own flag/command set, and a shared helper would let a
/// change to one root's set silently re-point the other's rows.
fn hoist_frps(args: &[&str]) -> Vec<String> {
    let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
    hoist_leading_subcommand(&argv, RootCommand::Frps)
        .into_iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect()
}

fn run_frps_cmd(args: &[&str]) -> Result<FrpsCmd, bpaf::ParseFailure> {
    let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
    let prepared = prepared_cli_argv(&argv, RootCommand::Frps);
    frps_parser().to_options().run_inner(&prepared[..])
}

/// The `frps` **run-path** parser ([`frps_args`]) only, for the assertions
/// that the two extensions are still accepted there. The whole surface is
/// [`run_frps_cmd`].
fn parse_frps_run(args: &[&str]) -> Result<FrpsArgs, bpaf::ParseFailure> {
    frps_args().to_options().run_inner(args)
}

fn run_frpc(args: &[&str]) -> Result<FrpcCmd, bpaf::ParseFailure> {
    let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
    let prepared = prepared_cli_argv(&argv, RootCommand::Frpc);
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
            consumes_value(OsStr::new(takes), RootCommand::Frpc),
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
            !consumes_value(OsStr::new(keeps), RootCommand::Frpc),
            "{keeps} must not swallow the next token"
        );
    }
}

// ── the `--help=<bool>` pass (TODO.md:4981) ─────────────────────────
//
// Every row in these two tests carries the Go v0.71.0 measurement it pins,
// taken with one fresh listening socket per run on the config's
// `[webServer] port` and the connection count read from `accept`:
// `--help=false status -c CFG` is rc 1 with **1** connection (`status` ran and
// dialled), `--help=true status -c CFG` is rc 0 with 0 connections and
// `status`'s help, and `-hc status` is rc 1 with the missing-argument line on
// stderr and 0 B on stdout.

/// Go's pflag bool makes `--help=false` a *value*, not a request: the command
/// still resolves and runs. bpaf's built-in help parser pre-empted that, so
/// the pass drops the token when a command word follows it and appends a bare
/// `--help` when the value is true.
#[test]
fn help_bool_value_form_is_stripped_only_before_a_command() {
    assert_eq!(
        prepared(&["--help=false", "status", "-c", "pA.toml"]),
        ["status", "-c", "pA.toml"]
    );
}

/// The shapes, measured one by one. `prepared` runs the whole chain the
/// binaries run — the config dash-value rewrite, the hoist, this pass and the
/// shorthand detector — so a row failing here is a row the binary would get
/// wrong.
#[test]
fn help_bool_value_form_rows_match_go() {
    // The command is hoisted past the flag, and the flag becomes a bare
    // `--help` **at the end** so the subcommand's own help is what prints
    // (`--help=true status` and `status --help` are byte-identical on Go).
    assert_eq!(
        prepared(&["--help=true", "status", "-c", "pA.toml"]),
        ["status", "-c", "pA.toml", "--help"]
    );
    assert_eq!(prepared(&["--help=true", "status"]), ["status", "--help"]);
    // `false` is dropped with no replacement, so the command runs.
    assert_eq!(
        prepared(&["--help=false", "status", "-c", "pA.toml"]),
        ["status", "-c", "pA.toml"]
    );
    assert_eq!(prepared(&["--help=false", "verify"]), ["verify"]);
    // The underscore-suffixed values Go's `strconv.ParseBool` accepts.
    assert_eq!(
        prepared(&["--help=0", "status", "-c", "pA.toml"]),
        ["status", "-c", "pA.toml"]
    );
    assert_eq!(prepared(&["--help=1", "status"]), ["status", "--help"]);
    // Every other spelling of the same key is left for bpaf, because it is
    // not `--help=<bool>`: `--help`, `-h`, `--helpfalse` (no `=`) and the
    // prefix `--helpful=x`.
    for untouched in [
        vec!["--help", "status"],
        vec!["-h", "status"],
        vec!["--helpfalse", "status"],
    ] {
        assert_eq!(
            prepared(&untouched),
            untouched,
            "{untouched:?} is not `--help=<bool>`"
        );
    }
    // `--helpful=x` is not `--help=<bool>` either, but it *is* a flag the
    // hoist sees as value-taking, so `status` is hoisted past it — the
    // pre-existing `unknown flag` treatment, unchanged by this pass.
    assert_eq!(
        prepared(&["--helpful=x", "status"]),
        ["status", "--helpful=x"]
    );
    // The space form is **not** `--help=<bool>`, but it is still hoisted:
    // `--help` is a consumer, so `false` is its value and `status` is the
    // first bare word. Pre-existing (the hoist predates this pass) and pinned
    // here so the two passes cannot start disagreeing about it.
    assert_eq!(
        prepared(&["--help", "false", "status"]),
        ["status", "--help", "false"]
    );
    // No command word → the pass leaves the token alone: this is the
    // pre-existing root divergence (`frpc --help=false -c cfg` prints help
    // here and starts the client on Go, rc 124, `TODO.md:4981`), and
    // `--help=true notacommand` must keep bpaf's refusal rather than be
    // cleaned up into root help.
    for untouched in [
        vec!["--help=false", "-c", "pA.toml"],
        vec!["--help=true"],
        vec!["--help=true", "notacommand"],
        vec!["--help=false", "notacommand"],
    ] {
        assert_eq!(
            prepared(&untouched),
            untouched,
            "{untouched:?} has no command word"
        );
    }
    // …and a word in `-c`'s value position is not a command word either, so
    // a `status` hiding there is never promoted to one — and the flag is not
    // stripped on its account.
    assert_eq!(
        prepared(&["--help=false", "-c", "status"]),
        ["--help=false", "-c", "status"]
    );
    // Nothing after a real `--` is a flag — `-c --help` is `-c`'s value, and
    // the rewrite has already attached it by the time this pass looks.
    assert_eq!(
        prepared(&["-c", "--help=false", "status"]),
        ["status", "-c=--help=false"]
    );
}

/// A `--help=<bool>` token that pflag hands to another flag as its **value**
/// is not a help request, and must survive untouched. R2's F1: six measured
/// rows where the head used to strip it and then fail or print help.
#[test]
fn a_help_token_in_a_value_position_is_not_a_request() {
    // `frpc -hc --help=false status` — the cluster's `c` takes the token, so
    // Go answers with **`status`'s** help and rc 0 (measured: 627 B,
    // `Overview of all proxies status`) and the base head agreed at 1604 B of
    // bpaf usage. Stripping the token left `-hc` dangling and refused an argv
    // both trees parse.
    assert_eq!(
        prepared(&["-hc", "--help=false", "status"]),
        ["status", "-hc", "--help=false"]
    );
    // The config flags: `--config` / `-c` take the token, so the config read
    // is what fails (Go: `open --help=false: no such file or directory`,
    // rc 1, 81 B on stdout) instead of a help print.
    // (`-c`'s dash-value rewrite runs first, so those two reach the hoist
    // as one attached token and the command is hoisted past them.)
    assert_eq!(
        prepared(&["--config", "--help=false", "status"]),
        ["status", "--config=--help=false"]
    );
    assert_eq!(
        prepared(&["-c", "--help=false", "status"]),
        ["status", "-c=--help=false"]
    );
    // …and `<long>=<value>` spellings keep their own `=`, so the pass never
    // sees them as `--help=`.
    assert_eq!(
        prepared(&["status", "--admin-addr=--help=false"]),
        ["status", "--admin-addr=--help=false"]
    );
}

/// pflag's consumption walk, and the argv that reached bpaf's help instead
/// of its error. Each `Some` row is a Go rc 1 whose line must be
/// `Error: flag needs an argument: '<c>' in -<c>`; each `None` row is argv
/// that must be left for the parser.
///
/// The rows go through the rewrite, the attachment and the expansion — the
/// passes that run before the refusal — but not `prepared`, which would call
/// the exiter. The walk is what decides: a `-h<short>` cluster *claims* the
/// token after it (`frpc -hc -hc`, `frpc -hc -v`), so only a cluster with
/// nothing left to take is reported.
#[test]
fn shorthand_cluster_needing_a_value_is_detected() {
    let prepared_before_reject = |args: &[&str]| {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        let rewritten = rewrite_config_dash_values(&argv);
        let attached = attach_flag_shaped_values(rewritten, RootCommand::Frpc);
        let hoisted = hoist_leading_subcommand(&attached, RootCommand::Frpc);
        expand_help_bool_value_form(hoisted, RootCommand::Frpc)
    };
    for (argv, expected) in [
        // Go rc 1, stderr, 0 B on stdout: the cluster is last and takes
        // nothing. `-hc status` also reports `c` — pflag hands `status` to
        // the cluster as its value and the *status* parser then sees `-hc`
        // with nothing after it (637 B, measured).
        (vec!["-hc"], Some('c')),
        (vec!["-hc", "status"], Some('c')),
        (vec!["status", "-hc"], Some('c')),
        (vec!["-c", "CFG", "-hc"], Some('c')),
        // Go rc 0 with root help (measured 1370 B): the cluster took the
        // next token, whatever it is.
        (vec!["-hc", "-hc"], None),
        (vec!["-hc", "-hL"], None),
        (vec!["-hc", "-h"], None),
        (vec!["-hc", "-v"], None),
        (vec!["-hc", "-c"], None),
        // …and the same once the hoist has moved the command word in front:
        // `frpc -hc status -v` / `-c` / `-c CFG` are all Go rc 0 (627 B of
        // `status` help).
        (vec!["-hc", "status", "-c"], None),
        (vec!["-hc", "status", "-c", "CFG"], None),
        (vec!["-hc", "status", "-v"], None),
        (vec!["-hc", "status", "-t"], None),
        // `-L` is frp-rs's run-path short, so the **root** context reports
        // it (Go has no `-L` at all: `unknown shorthand flag: 'L' in -L`,
        // rc 1 — the message differs, the rc and stream agree).
        (vec!["-hL"], Some('L')),
        // The subcommands of **both** binaries do not have `-L` in frp-rs, so
        // no fabricated `flag needs an argument: 'L'` line there.
        (vec!["status", "-hL"], None),
        (vec!["tcp", "-hL"], None),
        (vec!["verify", "-hL"], None),
        // A bare help flag followed by a bare dangling short is reported
        // (R2's F2): `frpc -h -c` is Go rc 1 with pflag's line on stderr.
        (vec!["-h", "-c"], Some('c')),
        (vec!["--help", "-t"], Some('t')),
        (vec!["status", "-h", "-c"], Some('c')),
        // …while the reverse order is the *short* taking `-h` as its value.
        (vec!["-t", "-h"], None),
        (vec!["-c", "-h"], None),
        // The cluster carries its value, or names something that cannot take
        // one.
        (vec!["-hcx"], None),
        (vec!["-hc=x"], None),
        (vec!["-hLinfo"], None),
        (vec!["-h"], None),
        (vec!["-c"], Some('c')),
        (vec!["--help=false"], None),
        (vec!["-h", "status"], None),
    ] {
        let items = prepared_before_reject(&argv);
        assert_eq!(
            walk_argv(
                &items,
                ShortFlagContext::of(&items, RootCommand::Frpc),
                RootCommand::Frpc
            )
            .needs_argument,
            expected,
            "{argv:?} reaches the walk as {items:?} and must be {expected:?}"
        );
    }
}

/// M1: the two **roots** do not share a short set. `-L` is `frpc`'s run-path
/// alias for `--log-level`; `frps`'s root has no such short in frp-rs *or* in
/// Go (`log_level` is registered with an empty shorthand,
/// `pkg/config/flags.go:244`). Sharing the sets made `frps -hL` print a
/// fabricated `flag needs an argument: 'L' in -L` where the base and Go are
/// rc 1 with bpaf's own refusal (measured: base == head, stderr 45 B).
#[test]
fn the_root_shorts_are_per_binary() {
    assert!(value_taking_root_shorts(RootCommand::Frpc).contains(&'L'));
    assert!(!value_taking_root_shorts(RootCommand::Frps).contains(&'L'));
    let argv: Vec<OsString> = ["-hL"].iter().map(OsString::from).collect();
    assert_eq!(
        walk_argv(
            &argv,
            ShortFlagContext::of(&argv, RootCommand::Frpc),
            RootCommand::Frpc
        )
        .needs_argument,
        Some('L'),
        "frpc's run path registers -L, so the cluster is reported"
    );
    assert_eq!(
        walk_argv(
            &argv,
            ShortFlagContext::of(&argv, RootCommand::Frps),
            RootCommand::Frps
        )
        .needs_argument,
        None,
        "frps has no -L, so nothing may be fabricated"
    );
}

/// A flag-shaped value is attached to the flag that owns it, because bpaf
/// cannot see a value that starts with `-`. R2's F2b: `frps -c CFG -t -h`
/// must take `-h` as `--token`'s value (Go loads the config and exits 1),
/// where the base head printed root help with rc 0.
#[test]
fn a_flag_shaped_value_is_attached_to_its_flag() {
    let attach = |args: &[&str]| {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        let rewritten = rewrite_config_dash_values(&argv);
        attach_flag_shaped_values(rewritten, RootCommand::Frps)
    };
    assert_eq!(attach(&["-c", "CFG", "-t", "-h"]), ["-c", "CFG", "-t=-h"]);
    assert_eq!(attach(&["-t", "-h"]), ["-t=-h"]);
    assert_eq!(attach(&["-p", "-h"]), ["-p=-h"]);
    // The **long** flags too, including a value that carries its own `=`:
    // `frps verify --token --help=false -c CFG` must hand `--help=false` to
    // `--token` (Go parses it and exits 0 with `syntax is ok`, 116 B; a
    // short-only list left `--token` with no argument and exited 1).
    assert_eq!(
        attach(&["verify", "--token", "--help=false", "-c", "CFG"]),
        ["verify", "--token=--help=false", "-c", "CFG"]
    );
    assert_eq!(
        attach(&["verify", "--bind-addr", "--help=false"]),
        ["verify", "--bind-addr=--help=false"]
    );
    assert_eq!(
        attach(&["verify", "--log_file", "--help=false"]),
        ["verify", "--log_file=--help=false"]
    );
    assert_eq!(attach(&["--log-level", "-h"]), ["--log-level=-h"]);
    // **Not** attached: the frp-rs bools, whose value branch is
    // `.adjacent()` so a separate token is never their value, and the names
    // frp-rs does not register at all. Attaching these was the round-3
    // regression: `frps verify --dashboard_tls_mode -c CFG` became
    // `--dashboard_tls_mode=-c` and the bool parser refused the value (Go and
    // the base: rc 0, 114 B on stdout), and `frpc tcp --disable-log-color -h`
    // / `--ue -h` / `--tls_enable -h` became errors where both trees print
    // help with rc 0.
    for untouched in [
        vec!["verify", "--dashboard_tls_mode", "-c", "CFG"],
        vec![
            "verify",
            "--dashboard-tls-mode",
            "--help=false",
            "-c",
            "CFG",
        ],
        vec!["tcp", "--disable-log-color", "-h"],
        vec!["tcp", "--ue", "-h"],
        vec!["tcp", "--uc", "-h"],
        vec!["stcp", "--tls_enable", "-h"],
        vec!["tcp", "--version", "-h"],
        vec!["status", "--json", "-h"],
        vec!["--strict-config", "-h"],
        vec!["-h", "-c"],
        vec!["-hc", "-h"],
    ] {
        assert_eq!(
            attach(&untouched),
            untouched,
            "{untouched:?} must be left alone"
        );
    }
    // The long list is what decides that, so pin its shape in both
    // directions: the names the measured rows need are members, and every
    // frp-rs bool is not.
    for member in [
        "token",
        "bind-addr",
        "bind-port",
        "bind_port",
        "log_file",
        "log-level",
        "config",
        "config_dir",
        "allow-unsafe",
        "proxy-name",
    ] {
        assert!(
            VALUE_TAKING_LONG_FLAGS.contains(&member),
            "{member} must be listed"
        );
    }
    for absent in [
        "ue",
        "uc",
        "tls_enable",
        "disable-log-color",
        "dashboard-tls-mode",
        "dashboard_tls_mode",
        "version",
        "strict-config",
        "strict_config",
        "json",
        "enable-prometheus",
        "tls-only",
    ] {
        assert!(
            !VALUE_TAKING_LONG_FLAGS.contains(&absent),
            "{absent} must not be listed"
        );
    }
    // Nothing to attach when the value is bare, and nothing to attach a
    // *bool* short to: `frpc -v -h` is `-v` plus a help request on both
    // trees, not `--version="-h"`.
    assert_eq!(attach(&["-c", "CFG", "-t", "X"]), ["-c", "CFG", "-t", "X"]);
    assert_eq!(attach(&["-v", "-h"]), ["-v", "-h"]);
    assert_eq!(attach(&["--help", "-h"]), ["--help", "-h"]);
    assert_eq!(attach(&["--version", "-h"]), ["--version", "-h"]);
    assert_eq!(
        attach(&["--strict-config", "-h"]),
        ["--strict-config", "-h"]
    );
    // A cluster is a consumer too: `frpc -hc -h` gives `-h` to the `c`.
    // A cluster is a consumer too, and `-v` is a bool short with no `-v=`
    // spelling, so only the flag-shaped value of a **config** flag is
    // attached as well (`frpc -c --help=false status` is
    // `-c=--help=false`, the rewrite that already existed).
    assert_eq!(attach(&["-hc", "status", "-v"]), ["-hc", "status", "-v"]);
    // An already-attached token is left alone, and `--` still ends the pass.
    assert_eq!(attach(&["-c=-h"]), ["-c=-h"]);
    assert_eq!(attach(&["--", "-t", "-h"]), ["--", "-t", "-h"]);
}

/// The **value grammar** and the rejection are pflag's even though the
/// *document* is now cobra's (rendered by `render_cobra_help`):
/// `--help=<anything not a `strconv.ParseBool`
/// spelling>` is refused with pflag's line and rc 1, which is a different
/// answer from the base head's root help (measured: Go rc 1, 698 B on
/// stderr for `--help=foo status`; base head rc 0, 1604 B of `status` usage
/// on stdout; head rc 1 with the same 102 B pflag-shaped line as the other
/// bool flags). The passing values are the twelve Go accepts, so this is a
/// table over `parse_go_bool`.
#[test]
fn help_bool_value_form_uses_go_bool_spellings() {
    for (value, is_true) in [
        ("1", true),
        ("t", true),
        ("T", true),
        ("TRUE", true),
        ("true", true),
        ("True", true),
        ("0", false),
        ("f", false),
        ("F", false),
        ("FALSE", false),
        ("false", false),
        ("False", false),
    ] {
        let mut args = vec![format!("--help={value}"), "status".to_string()];
        if !is_true {
            args.push("-c".to_string());
            args.push("pA.toml".to_string());
        }
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut expected = vec!["status"];
        if !is_true {
            expected.extend(["-c", "pA.toml"]);
        } else {
            expected.push("--help");
        }
        assert_eq!(prepared(&argv), expected, "--help={value}");
    }
    // Out-of-grammar values exit the process, so they cannot be observed
    // from inside this test binary; the binary-level rc and the exact
    // stderr line for `--help=foo` are measured in the probe (Go 698 B,
    // head 102 B, both rc 1 with 0 B on stdout) and recorded in
    // `docs/developing.md`.
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
    let prepared = prepared_cli_argv(
        &[OsString::from("--help"), OsString::from("status")],
        RootCommand::Frpc,
    );
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
/// the same set `FrpcCmd` in `mod.rs` declares, and the same set
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
        let prepared = prepared_cli_argv(&[OsString::from(name)], RootCommand::Frpc);
        let own_flag = single_proxy_own_flag(name);
        match frpc_parser().to_options().run_inner(&prepared[..]) {
            // The four admin commands are complete without further flags.
            Ok(cmd) => assert_eq!(
                command_variant_name(&cmd),
                Some(name),
                "{name} selected a different branch"
            ),
            Err(failure) => {
                let own_flag = own_flag
                    .unwrap_or_else(|| panic!("{name} must parse with no flags, got {failure:?}"));
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

/// The `frps` half of the pair above, in both directions, because
/// [`FRPS_SUBCOMMANDS`] is a new hand-written list and the whole point of
/// the list is that it matches [`frps_parser`].
///
/// Forward: every name in the list must select a command branch — here
/// `verify`, which parses with no further flags (Go registers `-c` with an
/// empty default on `frps`, `cmd/frps/root.go:44`, so the command is
/// complete bare). Reverse: the list must be exactly the `command("…")`
/// branches bpaf renders for `frps_parser`.
#[test]
fn the_frps_command_list_is_exactly_the_parser_branches() {
    for name in FRPS_SUBCOMMANDS {
        match run_frps_cmd(&[name]) {
            Ok(FrpsCmd::Verify(args)) => assert_eq!(
                args.config, "",
                "{name} bare must mean \"no config file specified\", the empty default Go \
                 registers for `-c`"
            ),
            other => panic!("{name} must select the verify branch, got {other:?}"),
        }
    }

    let failure = frps_parser()
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
        FRPS_SUBCOMMANDS.to_vec(),
        "the parser's command list and FRPS_SUBCOMMANDS disagree; help was:\n{text}"
    );
}

/// Cobra's `stripFlags` reads **this root command's** flag registry, so the
/// bool set is per root and the two sets are not interchangeable. Measured
/// on Go v0.71.0 (`docs/developing.md` § CLI inputs carries the table):
/// `frps --tls-only verify -c <cfg>`, `frps --enable-prometheus verify -c
/// <cfg>` and `frps --disable-log-color verify -c <cfg>` all resolve
/// `verify` (rc 0), so those three are pflag bools **on `frps`** — and the
/// same three names are ordinary flags on `frpc`, where they would swallow
/// a following token.
///
/// The reverse-direction row is `--dashboard-tls-mode`: it looks like the
/// other `--…-mode` flags but is registered with `VarP(BoolFuncFlag{…})`
/// (`pkg/config/flags.go:256-258`), which never sets `NoOptDefVal`.
/// Measured: `frps --dashboard-tls-mode verify -c <valid cfg>` consumes
/// `verify` as the flag's value, finds no bare word and **starts the
/// server** (killed by the 6 s probe watchdog at rc 143) instead of verifying. Treating it as
/// a bool here would hoist `verify` out of that argv and turn a running
/// server into a verify run.
#[test]
fn the_bool_root_flag_sets_are_per_root_command() {
    for keeps in [
        "--version",
        "-v",
        "--strict_config",
        "--strict-config",
        "--tls-only",
        "--tls_only",
        "--enable-prometheus",
        "--enable_prometheus",
        "--disable-log-color",
        "--disable_log_color",
    ] {
        assert!(
            !consumes_value(OsStr::new(keeps), RootCommand::Frps),
            "frps: {keeps} is a pflag bool (both spellings, through \
             WordSepNormalizeFunc) and must not swallow the next token"
        );
    }
    for takes in [
        "--dashboard-tls-mode",
        "--dashboard_tls_mode",
        "--bind-port",
        "--bind_addr",
        "-p",
        "-t",
        "--token",
        "--allow-ports",
        "--log-file",
        "--config-dir",
        "--nodash",
        "--help",
        "-h",
    ] {
        assert!(
            consumes_value(OsStr::new(takes), RootCommand::Frps),
            "frps: {takes} must swallow the next token"
        );
    }

    // `frpc` is unchanged by this, and the three frps-only bools are
    // consumers there — which is what makes the sets per-root rather than
    // one shared constant.
    for takes in [
        "--tls-only",
        "--enable-prometheus",
        "--disable-log-color",
        "--dashboard-tls-mode",
        "--allow-ports",
    ] {
        assert!(
            consumes_value(OsStr::new(takes), RootCommand::Frpc),
            "frpc: {takes} is not a pflag bool on this root and must swallow"
        );
    }
    for keeps in ["--version", "--strict-config", "--strict_config", "-v"] {
        assert!(
            !consumes_value(OsStr::new(keeps), RootCommand::Frpc),
            "frpc: {keeps} is a pflag bool and must not swallow"
        );
    }
}

/// The `frps` hoist rows, each measured on Go v0.71.0 with its own config
/// and port (`docs/developing.md` § CLI inputs). The command word moves past
/// leading root flags exactly when cobra would have resolved it, and the
/// first bare word is the only candidate:
///
/// * `-c cfg.toml verify` and `--strict-config=false verify -c cfg.toml` —
///   the flag does not swallow it, so Go runs `verifyCmd` (rc 0); the base
///   binary answered rc 1 `` `verify` is not expected in this context ``;
/// * `--tls-only` / `--enable-prometheus` / `--disable-log-color` /
///   `--version` / `--strict_config` before `verify` — all pflag bools, so
///   none of them consumes it (measured rc 0 on Go);
/// * `-p 7000 verify` — `-p` takes a value, so `verify` is that value's
///   *successor* and no hoist happens;
/// * `--dashboard-tls-mode verify` — that flag consumes `verify` itself, so
///   there is no command word at all (measured: Go starts the server);
/// * `--strict-config true verify` — the space form: `true` is the first
///   bare word, and it is not a command, so `verify` is never reached
///   (measured: `unknown command "true" for "frps"`, rc 1).
#[test]
fn frps_hoists_verify_past_its_own_root_flags() {
    for flag in [
        "--strict-config=false",
        "--strict_config=false",
        "--tls-only",
        "--enable-prometheus",
        "--disable-log-color",
        "--version",
        "-v",
    ] {
        assert_eq!(
            hoist_frps(&[flag, "verify", "-c", "cfg.toml"]),
            ["verify", flag, "-c", "cfg.toml"],
            "frps {flag} is a pflag bool and must not swallow `verify`"
        );
    }
    assert_eq!(
        hoist_frps(&["-c", "cfg.toml", "verify"]),
        ["verify", "-c", "cfg.toml"]
    );
    assert_eq!(
        hoist_frps(&["-c", "cfg.toml", "--strict-config=false", "verify"]),
        ["verify", "-c", "cfg.toml", "--strict-config=false"]
    );
    // `-c cfg.toml verify --strict-config=false` (the flag after the
    // command) needs no hoist, and must not be rewritten either.
    assert_eq!(
        hoist_frps(&["verify", "-c", "cfg.toml", "--strict-config=false"]),
        ["verify", "-c", "cfg.toml", "--strict-config=false"]
    );

    // `-p 7000 verify`: `-p` takes a value, so the value is consumed and
    // `verify` — the *next* token — is the first bare word and is resolved.
    // Measured on Go v0.71.0 (rc 0).
    assert_eq!(
        hoist_frps(&["-p", "7000", "verify", "-c", "cfg.toml"]),
        ["verify", "-p", "7000", "-c", "cfg.toml"]
    );

    for unchanged in [
        // A value-taking flag swallows the command word itself: `verify` is
        // `-t`'s **value**, so no bare word survives...
        &["-t", "verify"][..],
        // ...and the same for the flag that only *looks* like a bool.
        &["--dashboard-tls-mode", "verify", "-c", "cfg.toml"][..],
        // The first bare word is `true`, which is not a command.
        &["--strict-config", "true", "verify", "-c", "cfg.toml"][..],
        // A real separator stops the scan.
        &["-c", "cfg.toml", "--", "verify"][..],
        // A config file literally named `verify` is a value, not a command.
        &["-c", "verify"][..],
        // Already leading.
        &["verify", "-c", "cfg.toml"][..],
        // A word that is not a command anywhere in the list.
        &["notacommand", "verify"][..],
    ] {
        assert_eq!(
            hoist_frps(unchanged),
            unchanged,
            "{unchanged:?} must not be rewritten on `frps`"
        );
    }
}

/// The end of the chain on `frps`: the hoisted argv must reach the `verify`
/// branch with its config, which is the only reason the hoist exists (before
/// it, this argv was rc 1 `` `verify` is not expected in this context ``).
#[test]
fn the_hoisted_frps_argv_parses_as_verify() {
    match run_frps_cmd(&["-c", "cfg.toml", "verify"]).expect("hoisted argv parses") {
        FrpsCmd::Verify(args) => {
            assert_eq!(args.config, "cfg.toml");
            assert!(args.strict_config);
        }
        other => panic!("expected the verify command, got {other:?}"),
    }
    match run_frps_cmd(&["--strict-config=false", "verify", "-c", "cfg.toml"])
        .expect("hoisted argv parses")
    {
        FrpsCmd::Verify(args) => {
            assert_eq!(args.config, "cfg.toml");
            assert!(!args.strict_config);
        }
        other => panic!("expected the verify command, got {other:?}"),
    }
    // `verify` without `-c` is the empty-path case, not a parse failure:
    // Go's `-c` default is the empty string on frps.
    match run_frps_cmd(&["verify"]).expect("bare verify parses") {
        FrpsCmd::Verify(args) => assert_eq!(args.config, ""),
        other => panic!("expected the verify command, got {other:?}"),
    }
    // A value that names the command stays a value: run mode with the config
    // file `verify`, never the verify command.
    match run_frps_cmd(&["-c", "verify"]).expect("run mode with a config named verify") {
        FrpsCmd::Run(args) => assert_eq!(args.config.as_deref(), Some("verify")),
        other => panic!("expected the frps run path, got {other:?}"),
    }
    // No `-c` at all is still the run path (the default `frps.toml`), not
    // `verify` — the two are separated by the command word, not by absence.
    match run_frps_cmd(&["--bind-port", "7000"]).expect("run mode parses") {
        FrpsCmd::Run(args) => assert_eq!(args.bind_port, Some(7000)),
        other => panic!("expected the frps run path, got {other:?}"),
    }
}

/// The two **frp-rs-only** `frps` root flags must not ride into `verify`,
/// where Go's `frps` answers `unknown flag: …` with rc 1. They are the
/// complete extension set, measured by diffing the two binaries' rendered
/// `--help` flag lists: frp-rs-only = {`config-dir`, `log-format`}, with no
/// Go-only flag left (the former Go-only `vhost-http-timeout` is now
/// registered on `svr_transport`).
///
/// Measured on Go v0.71.0, stdout 0 B and stderr 1 line + usage in both
/// cases: `frps verify --log-format json -c <valid>` → rc **1** `Error:
/// unknown flag: --log-format`; `frps verify --config-dir <dir> -c <valid>`
/// → rc **1** `Error: unknown flag: --config-dir`. Before the
/// [`FrpsRootSlots`] fix the first printed `syntax is ok` and exited **0** —
/// a validation command reporting success for an argv Go rejects, exactly the
/// reason `--config-dir` was refused from the start.
///
/// `--log-format` is pinned in both directions: the run path still parses it
/// (a documented extension there, used as `frps --log-format json -c <cfg>`),
/// and the verify path refuses every spelling.
#[test]
fn frps_verify_refuses_the_run_paths_extension_flags() {
    assert_eq!(
        parse_frps_run(&["--log-format", "json"])
            .expect("the run path keeps the --log-format extension")
            .log_format
            .as_deref(),
        Some("json")
    );
    assert_eq!(
        parse_frps_run(&["--log_format", "json"])
            .expect("the underscore alias is the same run-path extension")
            .log_format
            .as_deref(),
        Some("json")
    );
    assert_eq!(
        parse_frps_run(&["--config-dir", "conf.d"])
            .expect("the run path keeps the --config-dir extension")
            .config_dir
            .as_deref(),
        Some("conf.d")
    );

    for args in [
        &["verify", "--log-format", "json", "-c", "x.toml"][..],
        &["verify", "--log_format", "json", "-c", "x.toml"][..],
        &["verify", "--log-format=json", "-c", "x.toml"][..],
        &["verify", "-c", "x.toml", "--log-format", "json"][..],
        &["verify", "--config-dir", "conf.d", "-c", "x.toml"][..],
        &["verify", "--config_dir", "conf.d", "-c", "x.toml"][..],
    ] {
        let err = run_frps_cmd(args)
            .expect_err(&format!("{args:?} must be refused on the verify path"))
            .unwrap_stderr();
        assert!(
            err.contains("is not expected in this context"),
            "{args:?} must be a leftover-token refusal naming the flag, got {err:?}"
        );
    }
}
