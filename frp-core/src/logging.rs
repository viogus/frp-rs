//! Shared logging and tracing initialization for frps and frpc binaries.
//!
//! Centralizes the duplicated `resolve_log_settings`, `init_logging`, and
//! `build_otel_layer` functions that were previously copied between
//! `frps/src/main.rs` and `frpc/src/main.rs`.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use tracing_subscriber::filter::{LevelFilter, Targets};

/// Resolve the effective log level: the CLI value wins over the config value,
/// which wins over the built-in default.
///
/// An **empty** CLI value counts as *not supplied* and falls through to
/// `cfg_level` when the caller has one, and to the built-in default when it does
/// not — `frps`'s `--config-dir` lane calls `init_logging(&cli, None)`, so it is
/// the `None` arm (`"info"`, or `_debug_default` under the `debug-logs`
/// feature). That is Go's value-level semantics: on Go the flag is bound with
/// its default (`pkg/config/flags.go:161` registers `--log_level` with
/// `"info"`), so `--log_level ""` leaves the struct empty and
/// `LogConfig.Complete()`'s `util.EmptyOr(c.Level, "info")`
/// (`pkg/config/v1/common.go:121`) fills it — measured on Go v0.71.0's
/// flags-only lane, where `frps --log_level ""` (no config file) still starts
/// the server and logs its **3 `[I]` records**: 282 B raw stdout / 249 B
/// ANSI-stripped, 0 B stderr on a free port. With the default port 7000 already
/// occupied on this host that lane instead exits 1: one 90 B `[I]` record
/// (`frps uses command line arguments for config`) plus an 83 B non-record
/// `create server listener error, listen tcp 0.0.0.0:7000: bind: address
/// already in use` line, 175 B stripped / 186 B raw in total. Treating
/// `Some("")` as a value instead routed the empty string to `parse_level`, where
/// `LevelFilter::from_str("")` is `Ok(ERROR)` — tracing-core 0.1.36 maps the
/// empty string to `ERROR` (`metadata.rs:798`) — and every startup record is
/// `INFO`. Measured on the pre-fix frp-rs binary: `--log-level ""` → 0 B stdout
/// / 0 B stderr with the listener up (the startup records are all `INFO`). See
/// `LogConfig::complete` (`frp-core/src/config/server.rs`) for the config-side
/// half of the same fill.
///
/// Where the fall-through *reaches* is the same on both binaries: an empty CLI
/// value counts as *not supplied*, so the config file's `level` wins whether the
/// caller is `frps` or `frpc`, and the built-in default applies only when no
/// config file supplied one.
///
/// `frps` is the only binary that overlays its CLI flags onto the loaded config
/// (`FrpsArgs::override_server_config`), and that overlay now skips the same
/// zero values this function filters — an empty `--log-level`/`--log-file` and
/// a zero `--log-max-days` — because `LogConfig::complete`
/// (`frp-core/src/config/server.rs`) would otherwise fill the overlaid zero to
/// Go's zero value (`info`/`console`/`3`) and *raise* a file's explicit `warn`.
/// Before that skip the two binaries disagreed whenever the file set a
/// non-default `level`: on the implicit `./frps.toml` lane, `frps` **before
/// `c8451157`** wrote the empty flag into `[log] level` (`override_server_config`
/// took every `Some`, empty or not) and `LogConfig::complete` then filled it to
/// `"info"`, so `--log-level ""` produced 11 `INFO` records where no flag gave
/// 0, while `frpc` honoured the file. That resolved-`info` output is what this
/// head binary still prints for `--log-level info` on the same lane: **11 `INFO`
/// records** with config `bindPort = 17531`, `[auth] token = "rev427token"`,
/// `[log] level = "warn"`. The record *count* is the stable observable, the byte
/// total is not: the `SIGUSR1 reload ready (pid=…)` record names the pid twice
/// (+2 B per pid digit) and the shutdown record's `elapsed_secs` width varies
/// (+1 B per character, 7–11 observed). ANSI-stripped that gave 1470–1473 B
/// across eight runs at this host's 5-digit pids (1471 B in the 4-digit sample),
/// with raw = stripped + 939 B of ANSI escapes.
///
/// **Go v0.71.0 has no disagreement to copy on the *empty* value.** With `-c`
/// Go discards the pflag-bound struct entirely (`cmd/frps/root.go:67-83`: the
/// `serverCfg` the flags were bound onto never reaches `runServer`), completing
/// the file's own struct instead (`pkg/config/load.go:313,318-321`) — which is
/// why the Go binary prints **0 records** on the config above for
/// `-c frps.toml`, `-c frps.toml --log-level ""` and even
/// `-c frps.toml --log-level info` alike. Go's only lane that completes an empty
/// level to `info` is the flags-only one: `frps --log_level ""` with no config
/// file fills `""` → `info` (`util.EmptyOr(Level, "info")`,
/// `pkg/config/v1/common.go:121`) and logs the 3 `[I]` records quoted above, the
/// first being `frps uses command line arguments for config`. frp-rs has no counterpart
/// lane — without `-c` it still reads `./frps.toml` (a missing file exits 1),
/// and `--config-dir` takes the `init_logging(&cli, None)` path
/// (`frps/src/main.rs:526`). `frpc`'s Go run path binds no `--log-level` flag at
/// all (`Error: unknown flag: --log-level`, rc 1), so the two binaries can be
/// compared on the value they resolve but not on the flag surface.
///
/// **R1 (closed): the *non-empty* CLI value on the `-c` lane now matches Go.**
/// Before the fix, on the config above `frps -c frps.toml --log-level info`
/// printed 11 `INFO` records where Go prints **0**: frp-rs gated only
/// `override_server_config` on `cli_overrides_enabled`
/// (`frps/src/main.rs:1082-1084`), while `init_logging` (`:1094`, defined at `:421`)
/// still read the raw CLI value. `init_logging` now masks the four CLI log flags
/// (`--log-level`, `--log-file`, `--log-max-days`, `--log-format`) whenever a
/// `-c` config was loaded, so the file's `[log]` section is authoritative there
/// exactly as it is for the config flags. Measured on the fixed binary over the
/// same file: `-c frps.toml --log-level info` → **0 B**, and
/// `-c frps.toml --log-level debug` → **0 B** too (the pre-fix binary answered
/// 11 `INFO` + 3 `DEBUG`), while the no-`-c` lane is unchanged at 11 `INFO`.
///
/// Not masked, and still divergent on that lane: `--disable-log-color`. Go's
/// `-c` branch discards the whole pflag-bound struct and hands
/// `log.InitLogger` the *file's* `Log.DisablePrintColor`
/// (`cmd/frps/root.go:112`), so Go ignores the flag there;
/// frp-rs still honours it, deliberately, and
/// `frps/tests/cli_exit_codes.rs::disable_log_color_value_spelling_is_applied`
/// pins that. R1 does not name the flag, so it is left for a separate item.
///
/// Pinned by
/// `frp-core/src/cli.rs::log_flag_zero_values_do_not_override_the_config_file`,
/// `frps/tests/cli_completion.rs::cli_empty_log_level_keeps_the_config_files_level`
/// and
/// `frps/tests/log_completion.rs::cli_nonempty_log_level_flag_does_not_override_the_config_file`.
pub fn resolve_log_level(
    cli_level: Option<String>,
    cfg_level: Option<&str>,
    _debug_default: &str,
) -> String {
    cli_level.filter(|l| !l.is_empty()).unwrap_or_else(|| {
        cfg_level
            .unwrap_or({
                #[cfg(feature = "debug-logs")]
                {
                    _debug_default
                }
                #[cfg(not(feature = "debug-logs"))]
                {
                    "info"
                }
            })
            .to_string()
    })
}

/// Resolve the log destination: `None` means stdout (`console`), `Some(path)`
/// means a rolling file at `path`. The CLI value wins over the config value.
///
/// An **empty** CLI value counts as *not supplied*, the same rule as
/// [`resolve_log_level`]: `--log-file ""` must mean "use the config's `to`"
/// (which is `console` in every default shape), not "roll a file at the empty
/// path". Measured on the pre-fix frp-rs binary: `--log-file ""` → 0 B stdout /
/// 0 B stderr **and** a `frps.log.<date>` created in the CWD, because the empty
/// path reached `tracing_appender::rolling::daily` (whose `file_name()` is
/// `None`, so it fell back to the default log name). Go v0.71.0 with
/// `--log_file ""` on the flags-only lane also logs on stdout — `""` is filled
/// to `console` by the same `Complete()` (`pkg/config/v1/common.go:120`) —
/// measured as 3 `[I]` records / 282 B raw / 0 B stderr on a free port.
///
/// Only the **CLI** value is filtered. An empty *config* value was already
/// resolved to `console` by this function before the completion existed (the
/// `cfg_file.is_empty()` arm below), so the file-lane `to = ""` shape was
/// **never** silent — measured at this head on the implicit `./frps.toml` lane
/// with `[log] to = ""` (`bindPort = 17533`): the 7 startup `INFO` records still
/// print and no log file is created in the CWD (that lane passes no CLI flag, so
/// the branch's filter cannot change it). The defect this filter closes is the
/// flag arm.
///
/// **The empty CLI value is filtered twice, and the second filter is what
/// makes the file's destination survive.** `FrpsArgs::override_server_config`
/// (`frp-core/src/cli.rs`) skips an empty `--log-file ""`, so the loaded file's
/// `to` reaches this function; without that skip, `LogConfig::complete` would
/// fill the clobbered `""` with the concrete `"console"`
/// (`EmptyOr(c.To, "console")`, `pkg/config/v1/common.go:120`) and this filter
/// would fall through to the completed value instead of the file's. Measured at
/// head with `[log] to = "logs/frps.log"`: no CLI flag → 0 B stdout and
/// `logs/frps.log.<date>` written; `--log-file ""` → the same file lane and 0 B
/// stdout (pre-fix: 2735 B stdout and `logs/` never created).
///
/// Go's `-c` lane arbitrates this field the same way — measured `frps -c
/// cfg.toml --log_file ""` → stdout 0 B with the configured file written — so
/// the file's destination governs on every lane that has a config file. Go's
/// *flags-only* lane has no file value to preserve and completes its empty flag
/// to `"console"` (measured `--log_file ""` byte-identical to omitting it,
/// 282 B / 3 `INFO` records), which is what this filter produces there too.
pub fn resolve_log_file(cli_file: Option<String>, cfg_file: &str) -> Option<String> {
    cli_file.filter(|f| !f.is_empty()).or_else(|| {
        if cfg_file.is_empty() || cfg_file == "console" {
            None // "console" means stdout (Go frp compat)
        } else {
            Some(cfg_file.to_string())
        }
    })
}

/// Resolve `log.maxDays` / `--log-max-days`: the CLI value wins over the config
/// value, which wins over the built-in `3`.
///
/// The CLI arm filters the **zero** value, because zero is Go's `util.EmptyOr`
/// zero value: Go binds `--log_max_days` straight onto the struct
/// (`pkg/config/flags.go:163`, default `3`) and then completes it
/// (`cmd/frps/root.go:77-83` → `LogConfig.Complete()`,
/// `pkg/config/v1/common.go:122` `MaxDays = util.EmptyOr(MaxDays, 3)`), so
/// `--log_max_days 0` means **3** on Go, not "retain forever". Only the CLI arm
/// filters zero; the config arm is the value `LogConfig::complete` already
/// filled, so a zero there means a caller skipped completion.
///
/// Without this filter the raw CLI value beat the value
/// [`LogConfig::complete`](crate::config::LogConfig::complete) had just filled,
/// because `frps`/`frpc` read `cli.log_max_days.or(cfg.log.max_days)`: the flag
/// had already overlaid `0` onto the config and completion had rewritten it to
/// `3`, then `Some(0)` won anyway.
///
/// **On Go this field has no startup observable at all**, which is why the
/// frp-rs rows are measured with a local aged-file fixture: the logger sweeps
/// only at the midnight rotation. `clearFiles()` has exactly one caller —
/// `rotate()` (`golib@v0.8.2/log/output_rotatefile.go:103`) — and `rotate()` is
/// reached only from `dailyRotate`'s 0:00 boundary (`Init` `:60-70` starts
/// `go fw.dailyRotate()` at `:68`; `:178-199` waits to the next hour and
/// rotates only `if nextHour.Hour() == 0` at `:193` → `fw.Rotate()` at `:194`).
/// `pkg/util/log/log.go:53-58` constructs the writer with
/// `Mode: RotateFileModeDaily` and calls only `Init()`, so **Go's cleanup is
/// midnight-only and never runs at startup** — no bounded probe can observe a
/// `MaxDays` difference on the Go binary, and the Go flags-only row above
/// (3 `[I]` records) cannot discriminate this field. The corollary is worth recording:
/// frp-rs's synchronous startup sweep is itself a pre-existing *timing*
/// divergence from Go, which is what makes the aged-file method work against
/// frp-rs and not against Go. `clearFiles()` also returns early when
/// `Mode == Daily && MaxDays <= 0` (`:242-244`), so "a zero or negative
/// `MaxDays` disables cleanup" is Go-true as well.
///
/// The frp-rs observable **is** synchronous startup cleanup (`init_tracing`
/// calls [`cleanup_expired_logs`] before the process serves). Measured at head
/// with a backdated `logs/frps.log.2020-01-01` whose mtime is five days old and
/// `[log] to = "logs/frps.log"` + `max_days = 7`: the fixture **survives** both
/// with no flag and with `--log-max-days 0` — the overlay skips the zero, so the
/// file's 7 governs — and is **deleted** by `--log-max-days 3`, a non-zero value
/// that still wins. With no `[log] max_days` key in the file, the absent key
/// takes serde's default 3 and `--log-max-days 0` deletes the same fixture, so
/// the flag is observationally absent there too. Only the zero value is filtered:
/// a negative CLI value is explicit on Go too (`util.EmptyOr(-1, 3)` is `-1`,
/// cleanup disabled) and passes through.
pub fn resolve_log_max_days(cli_max_days: Option<i32>, cfg_max_days: Option<i32>) -> i32 {
    cli_max_days
        .filter(|d| *d != 0)
        .or(cfg_max_days)
        .unwrap_or(3)
}

pub fn resolve_ansi(disable_log_color: bool) -> bool {
    !disable_log_color
}

/// Resolve the log output format. CLI wins over the config file (matching the
/// `resolve_log_level` / `resolve_log_file` precedence). Only "text" and
/// "json" are supported; any other value falls back to "text" with a warning
/// (Go frp `log.format` semantics).
pub fn resolve_log_format(cli_format: Option<String>, cfg_format: &str) -> String {
    let f = cli_format.unwrap_or_else(|| cfg_format.to_string());
    if f.is_empty() {
        return "text".into();
    }
    match f.as_str() {
        "text" | "json" => f,
        other => {
            eprintln!(
                "WARNING: unsupported log format '{other}', falling back to 'text' (supported: text, json)"
            );
            "text".into()
        }
    }
}

/// Pure predicate: is a log file with mtime `modified` older than `max_days`
/// days relative to `now`? `max_days <= 0` disables cleanup entirely (Go frp
/// `log.maxDays` semantics: never delete). A file with an mtime in the future
/// is never expired.
pub fn is_log_expired(modified: SystemTime, now: SystemTime, max_days: i32) -> bool {
    if max_days <= 0 {
        return false;
    }
    let cutoff = match now.checked_sub(Duration::from_secs(max_days as u64 * 24 * 60 * 60)) {
        Some(c) => c,
        None => return false,
    };
    modified < cutoff
}

/// Delete this program's rolling log files in `dir` whose file names start
/// with `log_name.` (the `tracing_appender::rolling::daily` naming scheme,
/// e.g. `frps.log.2026-08-07`) and whose mtime is older than `max_days` days.
///
/// Only files carrying the given prefix are ever touched — other files and
/// subdirectories in the directory are left alone. Read/stat/delete failures
/// are logged as warnings and never panic. Returns the number of files removed.
pub fn cleanup_expired_logs(dir: &Path, log_name: &str, max_days: i32) -> usize {
    if max_days <= 0 {
        return 0;
    }
    let prefix = format!("{log_name}.");
    let now = SystemTime::now();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                dir = %dir.display(),
                error = %e,
                "log cleanup: cannot read log directory"
            );
            return 0;
        }
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(&prefix) {
            continue;
        }
        // Never remove directories, even if their names match the prefix.
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let modified = match std::fs::metadata(&path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "log cleanup: cannot stat log file"
                );
                continue;
            }
        };
        if !is_log_expired(modified, now, max_days) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {
                tracing::info!(path = %path.display(), "log cleanup: removed expired log file");
                removed += 1;
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "log cleanup: failed to remove expired log file"
                );
            }
        }
    }
    removed
}

/// Spawn a background task that re-runs [`cleanup_expired_logs`] once every 24
/// hours. Must be called from within a Tokio runtime. No-op when
/// `max_days <= 0` (startup-time cleanup already ran synchronously).
fn spawn_daily_log_cleanup(dir: PathBuf, log_name: String, max_days: i32) {
    if max_days <= 0 {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
        // tokio's interval fires its first tick immediately; consume it so the
        // first *scheduled* cleanup happens one day after startup.
        interval.tick().await;
        loop {
            interval.tick().await;
            cleanup_expired_logs(&dir, &log_name, max_days);
        }
    });
}

/// Build a [`Targets`] filter from the `RUST_LOG` env var, falling back to a
/// bare `default_level` when the variable is unset or unparseable.
///
/// Replaces `EnvFilter::try_from_default_env()` so the `env-filter` feature —
/// and with it the `matchers` + `regex-automata` + `regex-syntax` chain
/// (~131 KiB per release binary) — can be dropped.
///
/// Supported `RUST_LOG` syntax (the static `Targets` grammar, verified
/// against tracing-subscriber 0.3.23):
///   - bare level: `debug`, `info`, `warn`, `error`, `trace`, `off`
///   - numeric levels `0`..`5` (`0`=off, `5`=trace) — accepted anywhere a
///     level token is (`3`, `frp_core=4`)
///   - `target=level`: `frp_core=debug`, `rustls=trace` (level names are
///     case-insensitive)
///   - bare target (no `=`): `frp_core` → that target at `trace`
///   - field-name lists: `target[{field}]=level` (name presence, no regex)
///   - comma-separated list of the above
///
/// Divergences from `EnvFilter` (all verified against the 0.3.23 static
/// parser):
///   - **Whole-string failure.** One malformed directive fails the ENTIRE
///     parse, so `filter_from_env` falls back to `default_level` — reported
///     on stderr, since logging is not initialized yet. Malformed means: an
///     unparseable level token after `=` (`frp_core=bogus` — every
///     `EnvFilter` field-*value* matcher lands here, because its
///     `]`-terminated value can never parse as a level:
///     `foo[span{name=x}]`, `foo[bar=baz]`), a second `=` (`a=b=c`,
///     `foo[span{name=x}]=trace`), or a malformed `[{...}]` field list.
///   - **`-target` exclusions and `target::*=level` glob suffixes parse as
///     inert literals.** `info,-tokio` and `foo::*=debug` are ACCEPTED (no
///     fallback) but never match anything: the literal strings `-tokio` and
///     `foo::*` prefix-match no real module path, so those directives
///     silently do nothing. EnvFilter would give them exclusion / glob
///     semantics; frp-rs has neither — a `RUST_LOG` relying on them must be
///     rewritten as explicit `target=level` pairs. Bare numeric tokens
///     outside 0..5 (`6`) are the same kind of inert literal target.
///   - **No regex.** `EnvFilter`'s field-value matchers and `span{...}`
///     scoping (the source of the regex dependency this filter replaces)
///     are unsupported and fail the parse as described above.
pub fn filter_from_env(default_level: &str) -> Targets {
    let fallback = || Targets::new().with_default(parse_level(default_level));
    match std::env::var("RUST_LOG") {
        Ok(raw) => {
            let trimmed = raw.trim();
            match trimmed.parse::<Targets>() {
                Ok(filter) => filter,
                Err(e) => {
                    // Pre-init: no logger exists yet, so stderr is the only
                    // channel. Without this a typo'd RUST_LOG silently
                    // discards the operator's whole filter (all-or-nothing
                    // fallback above).
                    eprintln!(
                        "frp: ignoring RUST_LOG={trimmed:?}: {e}; falling back to default level"
                    );
                    fallback()
                }
            }
        }
        Err(_) => fallback(),
    }
}

fn parse_level(s: &str) -> LevelFilter {
    LevelFilter::from_str(s).unwrap_or(LevelFilter::INFO)
}

pub fn init_tracing(
    level: &str,
    file: Option<String>,
    max_days: i32,
    format: &str,
    ansi: bool,
    default_log_name: &str,
) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Layer;

    let filter = filter_from_env(level);
    if let Some(path) = file {
        let dir = Path::new(&path).parent().unwrap_or(Path::new("."));
        let log_name = Path::new(&path)
            .file_name()
            .unwrap_or(std::ffi::OsStr::new(default_log_name))
            .to_string_lossy()
            .into_owned();
        let file_appender = tracing_appender::rolling::daily(dir, &log_name);
        if format == "json" {
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(ansi)
                        .json()
                        .with_writer(file_appender)
                        .with_filter(filter),
                )
                .init();
        } else {
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(ansi)
                        .with_writer(file_appender)
                        .with_filter(filter),
                )
                .init();
        }
        // Startup cleanup + daily cleanup run after the subscriber is live so
        // their warnings are recorded in the log.
        if max_days > 0 {
            cleanup_expired_logs(dir, &log_name, max_days);
            spawn_daily_log_cleanup(dir.to_path_buf(), log_name, max_days);
        }
    } else if format == "json" {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(ansi)
                    .json()
                    .with_filter(filter),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(ansi)
                    .with_filter(filter),
            )
            .init();
    }
}

/// Initialize a console (stdout) logger using the `RUST_LOG` filter with a
/// default of `info`. Used by the frpc `verify` and single-proxy subcommands,
/// which run standalone and need a subscriber before any config is loaded.
pub fn init_console_logger() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Layer;
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(filter_from_env("info")))
        .init();
}

/// Whether **this build of `frp-core`** carries the `otel` feature.
///
/// Exists so a crate that cannot name the feature can still ask about it: `otel`
/// is declared by `frps`/`frpc` (forwarding `frp-core/otel`), and `frp-server`
/// declares none of its own, so `#[cfg(feature = "otel")]` there is always false
/// even in a build where the OTLP exporter *is* compiled. Cargo unifies
/// `frp-core`'s features, so this const — evaluated where the feature really
/// lives — is `true` exactly when [`init_tracing_otel`] and [`build_otel_layer`]
/// are compiled in.
///
/// It tracks `frp-core`, not one specific dependent: a build that enables
/// `frp-core/otel` through another member while the binary under test does not is
/// a build where this is `true` and that binary's own `#[cfg(feature = "otel")]`
/// block is absent.
pub const OTEL_ENABLED: bool = cfg!(feature = "otel");

#[cfg(feature = "otel")]
#[allow(clippy::too_many_arguments)]
pub fn init_tracing_otel(
    level: &str,
    file: Option<String>,
    max_days: i32,
    format: &str,
    ansi: bool,
    service_name: &str,
    otlp_endpoint: Option<String>,
    default_log_name: &str,
) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    let (otel_layer, _provider) = if let Some(ref ep) = otlp_endpoint {
        match build_otel_layer(ep, service_name) {
            Ok((l, p)) => (Some(l), Some(p)),
            Err(e) => {
                eprintln!(
                    "WARNING: OTel init failed (endpoint={ep}): {e}. Tracing without OTLP export."
                );
                (None, None)
            }
        }
    } else {
        (None, None)
    };
    let filter = filter_from_env(level);
    // Layer order (innermost → outermost): Registry ← OTel Layer ← filter ← Fmt Layer
    // OpenTelemetryLayer requires direct Registry, so it must be applied first.
    // fmt::layer() must be constructed inline per branch: dyn Layer is fixed
    // to a single Subscriber type parameter and cannot compose with the
    // Layered<Targets, ...> chain.
    if let Some(path) = file {
        let dir = Path::new(&path).parent().unwrap_or(Path::new("."));
        let log_name = Path::new(&path)
            .file_name()
            .unwrap_or(std::ffi::OsStr::new(default_log_name))
            .to_string_lossy()
            .into_owned();
        let fa = tracing_appender::rolling::daily(dir, &log_name);
        let reg = tracing_subscriber::registry();
        // Keep the provider for the process lifetime, where `shutdown_otel`
        // can find it on the exit path.
        store_otel_provider(_provider);
        let json = format == "json";
        // A file destination means the records go to the file and nowhere
        // else — the same rule the non-otel `init_tracing` applies above.
        // The otel branch used to install a stdout fmt layer *as well*, so
        // `[log] to = "..."` mirrored every record to stdout in an otel build
        // (and `cli_empty_log_file_keeps_the_files_destination` failed in the
        // all-features lane). The OTel layer is orthogonal: spans still export
        // through the provider, only the console duplication is gone.
        match (otel_layer, json) {
            (Some(layer), true) => {
                reg.with(layer)
                    .with(filter)
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(false)
                            .json()
                            .with_writer(fa),
                    )
                    .init();
            }
            (Some(layer), false) => {
                reg.with(layer)
                    .with(filter)
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(false)
                            .with_writer(fa),
                    )
                    .init();
            }
            (None, true) => {
                reg.with(filter)
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(false)
                            .json()
                            .with_writer(fa),
                    )
                    .init();
            }
            (None, false) => {
                reg.with(filter)
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(false)
                            .with_writer(fa),
                    )
                    .init();
            }
        }
        // Startup cleanup + daily cleanup run after the subscriber is live so
        // their warnings are recorded in the log.
        if max_days > 0 {
            cleanup_expired_logs(dir, &log_name, max_days);
            spawn_daily_log_cleanup(dir.to_path_buf(), log_name, max_days);
        }
    } else {
        let reg = tracing_subscriber::registry();
        // Keep the provider for the process lifetime, where `shutdown_otel`
        // can find it on the exit path.
        store_otel_provider(_provider);
        if let Some(layer) = otel_layer {
            if format == "json" {
                reg.with(layer)
                    .with(filter)
                    .with(tracing_subscriber::fmt::layer().with_ansi(ansi).json())
                    .init();
            } else {
                reg.with(layer)
                    .with(filter)
                    .with(tracing_subscriber::fmt::layer().with_ansi(ansi))
                    .init();
            }
        } else if format == "json" {
            reg.with(filter)
                .with(tracing_subscriber::fmt::layer().with_ansi(ansi).json())
                .init();
        } else {
            reg.with(filter)
                .with(tracing_subscriber::fmt::layer().with_ansi(ansi))
                .init();
        }
    }

    // `build_otel_layer` ran before this subscriber existed, so the `https://`
    // record it emitted reached no sink. Repeat it now that one is installed:
    // otherwise a daemon with an endpoint the exporter cannot reach still
    // starts with no trace at all and no explanation.
    if let Some(endpoint) = otlp_endpoint.as_deref().filter(|ep| endpoint_is_https(ep)) {
        tracing::error!(endpoint = endpoint, "{}", OTLP_PLAIN_HTTP_ONLY);
    }
}

/// Append the OTLP/HTTP per-signal path (`/v1/traces`) to a **base** endpoint.
///
/// `opentelemetry-otlp` 0.33 appends the signal path only to the endpoints it
/// resolves itself (the `OTEL_EXPORTER_OTLP_*` environment variables and its
/// defaults); a string handed to `with_endpoint` is used as the request URI
/// verbatim. So a base-URL value passed to `init_tracing_otel`
/// (`http://collector:4318`) got `POST /`, a collector 404, and — the SDK's
/// `internal-logs` feature being off — no error anywhere: every span vanished
/// silently. This is the missing half of that contract for the programmatic
/// path.
///
/// The OTLP/HTTP spec's own rule is generic: *any* base URL gains the signal
/// path appended, so `http://host:4318/mycollector` would become
/// `.../mycollector/v1/traces`. This function deliberately does **not** extend
/// a non-root path: rewriting an endpoint that carries a path is the riskier
/// half of the change, and the only broken shape the bug report covered was
/// pathless. Non-root paths are therefore the caller's own choice.
///
/// Rules, in the order they are applied:
///
/// * anything without a `scheme://authority` shape is returned **verbatim** —
///   the old code raised no error for it and this must not invent one;
/// * a path that is absent (`http://host:4318`) or exactly `/`
///   (`http://host:4318/`) is a base URL: `/v1/traces` is appended. This is the
///   one behaviour change: both shapes previously went to the collector as
///   `POST /`, which an OTLP/HTTP receiver does not serve, so the request now
///   addresses the signal path the protocol defines;
/// * any other path is left alone — including an endpoint that already carries
///   `/v1/traces`, so an endpoint with a non-root path is byte-identical;
/// * a query string (and/or fragment) is carried across:
///   `http://host:4318?x=1` ⇒ `http://host:4318/v1/traces?x=1`.
#[cfg(feature = "otel")]
fn normalize_otlp_endpoint(endpoint: &str) -> String {
    // `scheme://` must be present and the scheme must look like one. A value
    // that misses either test is not a URL this function can reason about.
    let Some(scheme_end) = endpoint.find("://") else {
        return endpoint.to_string();
    };
    let scheme = &endpoint[..scheme_end];
    let mut scheme_chars = scheme.chars();
    let scheme_ok = scheme_chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !scheme_ok {
        return endpoint.to_string();
    }

    // Authority ends at the first `/`, `?` or `#`; an empty one (`http://`)
    // names no host, so it is not a base URL either.
    let after_scheme = &endpoint[scheme_end + 3..];
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let (authority, tail) = after_scheme.split_at(authority_end);
    if authority.is_empty() {
        return endpoint.to_string();
    }

    let (path, suffix) = match tail.find(['?', '#']) {
        Some(i) => tail.split_at(i),
        None => (tail, ""),
    };
    if !path.is_empty() && path != "/" {
        return endpoint.to_string();
    }

    format!("{scheme}://{authority}/v1/traces{suffix}")
}

/// The OTLP exporter this build ships has no TLS connector, so an `https://`
/// endpoint would be accepted and then export nothing.
#[cfg(feature = "otel")]
const OTLP_PLAIN_HTTP_ONLY: &str =
    "the OTLP/HTTP exporter only supports http:// endpoints; spans will not be exported";

/// Whether `endpoint` asks for the scheme the bundled exporter cannot reach.
///
/// Scheme comparison is ASCII-case-insensitive, the way a URL's scheme is.
#[cfg(feature = "otel")]
fn endpoint_is_https(endpoint: &str) -> bool {
    endpoint
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}

/// Build the OTLP/HTTP exporter, the batch span processor that drains it, and
/// the [`opentelemetry_sdk::trace::SdkTracerProvider`] tying them together.
///
/// This is the whole outbound half of the `otel` feature; [`build_otel_layer`]
/// only adds the `tracing` layer on top. It is `pub` + `#[doc(hidden)]` rather
/// than `pub(crate)` so that `frp-core/tests/otel_export.rs` can drive the
/// *production* wiring: an integration test is a separate crate, so a
/// `pub(crate)` helper would be invisible to it and the test would have to
/// rebuild the provider itself — exactly the copy that lets a wiring bug hide.
///
/// **Only `http://` is supported.** The `hyper-client` OTLP transport builds a
/// plain `HttpConnector`, so an `https://` endpoint is accepted here and then
/// never connects — measured: zero TCP connects, no span exported. That must
/// not be silent, so this function emits a `tracing::error!` for such an
/// endpoint, but it still returns a working provider: a daemon that is healthy
/// apart from tracing must not refuse to start. Callers that install their
/// subscriber *after* this call (the daemons do) repeat the record at init so
/// it lands in the log.
#[cfg(feature = "otel")]
#[doc(hidden)]
pub fn build_otel_provider(
    endpoint: &str,
    service_name: &str,
) -> Result<opentelemetry_sdk::trace::SdkTracerProvider, Box<dyn std::error::Error>> {
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::WithExportConfig as _;
    use opentelemetry_sdk::Resource;
    if endpoint_is_https(endpoint) {
        tracing::error!(endpoint = endpoint, "{}", OTLP_PLAIN_HTTP_ONLY);
    }
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(normalize_otlp_endpoint(endpoint))
        .build()?;
    let resource = Resource::builder_empty()
        .with_attributes(vec![KeyValue::new(
            "service.name",
            service_name.to_string(),
        )])
        .build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        // The async-runtime batch processor, *not* `with_batch_exporter`: in
        // 0.33 the latter picks the thread-based processor, which drives the
        // exporter with `futures_executor::block_on` on a plain OS thread.
        // The `hyper-client` OTLP exporter needs a tokio reactor, so that
        // worker panics on its first export —
        //   panicked at opentelemetry-http-0.33.1/src/lib.rs:330:13:
        //   there is no reactor running, must be called from the context of a Tokio 1.x runtime
        // — the thread dies and every span is silently dropped. This variant
        // spawns the batch task on the ambient tokio runtime; both daemons call
        // `init_tracing_otel` from inside `#[tokio::main]`.
        .with_span_processor(
            opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor::builder(
                exporter,
                opentelemetry_sdk::runtime::Tokio,
            )
            .build(),
        )
        .with_resource(resource)
        .build();
    Ok(provider)
}

#[cfg(feature = "otel")]
pub fn build_otel_layer(
    endpoint: &str,
    service_name: &str,
) -> Result<
    (
        tracing_opentelemetry::OpenTelemetryLayer<
            tracing_subscriber::Registry,
            opentelemetry_sdk::trace::Tracer,
        >,
        opentelemetry_sdk::trace::SdkTracerProvider,
    ),
    Box<dyn std::error::Error>,
> {
    use opentelemetry::trace::TracerProvider as _;
    let provider = build_otel_provider(endpoint, service_name)?;
    let tracer = provider.tracer("frp-rs");
    Ok((tracing_opentelemetry::layer().with_tracer(tracer), provider))
}

/// The provider [`init_tracing_otel`] built, held for the process lifetime so
/// the exit path can flush it.
///
/// The provider used to be `Box::leak`ed on both wiring branches: nothing owned
/// it, so nothing could call `shutdown()` and the batch still queued when the
/// daemon exited waited for the batch processor's first periodic export —
/// measured at 10.006 s on the SDK defaults — and was lost. It lives in a
/// `Mutex` rather than behind a `OnceLock` because [`shutdown_otel`] has to
/// *move* it out — that is what makes a second call a no-op instead of a second
/// `shutdown()` on an already-shut-down provider.
#[cfg(feature = "otel")]
static OTEL_PROVIDER: std::sync::Mutex<Option<opentelemetry_sdk::trace::SdkTracerProvider>> =
    std::sync::Mutex::new(None);

/// Lock [`OTEL_PROVIDER`], treating a poisoned lock as "the previous holder
/// panicked" rather than a second panic.
///
/// The exit path is the last place that may abort: a panic while the slot was
/// held (nothing holds it across a yield, but the cost of assuming so is a
/// process that panics *instead of* flushing) must not turn the flush into
/// another panic. The same reasoning as `lock_dir_registry` in `frps`.
#[cfg(feature = "otel")]
fn lock_otel_provider(
) -> std::sync::MutexGuard<'static, Option<opentelemetry_sdk::trace::SdkTracerProvider>> {
    OTEL_PROVIDER.lock().unwrap_or_else(|e| e.into_inner())
}

/// Hand the provider from [`build_otel_layer`] to the process-wide holder.
#[cfg(feature = "otel")]
fn store_otel_provider(provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>) {
    let Some(provider) = provider else { return };
    *lock_otel_provider() = Some(provider);
}

/// Flush and shut down the OTLP exporter, if one was initialised.
///
/// Call this once on the daemon's exit path: `SdkTracerProvider::shutdown()`
/// waits for the batch span processor to drain — that is what gets the last
/// batch of spans onto the wire — and then stops its task. Without it, spans
/// still queued when the process exits wait for the batch processor's first
/// periodic export (measured at 10.006 s on the SDK defaults) and are lost.
///
/// Idempotent: the provider is *taken* out of [`OTEL_PROVIDER`], so the second
/// call finds `None` and returns immediately. Safe to call unconditionally —
/// with the `otel` feature off this is the empty function below, so `frps` and
/// `frpc` need no `#[cfg]` at the call site.
///
/// **Supported contexts: a multi-thread tokio runtime, or no runtime at all.**
/// Blocking: the SDK's `shutdown()` waits on a oneshot channel for the batch
/// task. Called from inside `#[tokio::main]` (both daemons do, and both are
/// multi-thread), a direct wait would starve that task on a runtime that has no
/// other free worker, so a multi-thread runtime hands the worker's tasks off
/// with [`tokio::task::block_in_place`] first. With no runtime there is nothing
/// to starve and the wait is direct.
///
/// On a `current_thread` runtime queued spans are **not guaranteed** to be
/// exported. The batch task lives on that one runtime thread, so it cannot run
/// while the thread waits, and a blocking wait (including the one `Drop` would
/// do) would deadlock the runtime. That arm therefore spawns a detached thread
/// and returns without waiting; it can still flush when the runtime outlives
/// this call (a mid-run callback), but when the process exits immediately after
/// the call the batch is dropped — measured 0 of 3 runs, and giving the process
/// an extra 800 ms of life did not help. A `tracing::warn!` records the
/// condition. Neither daemon takes this path; do not add a daemon that does.
#[cfg(feature = "otel")]
pub fn shutdown_otel() {
    let Some(provider) = lock_otel_provider().take() else {
        return;
    };
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        // `block_in_place` moves the current worker's tasks to another worker
        // (spawning one when this is the only worker), so the batch task keeps
        // being polled while this thread waits for its answer.
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => {
            tokio::task::block_in_place(|| shutdown_provider(&provider));
        }
        // Not a tokio thread: no runtime to starve.
        Err(_) => shutdown_provider(&provider),
        // `current_thread`: any wait here blocks the one thread that can poll
        // the batch task, so this call must not wait. The detached thread is
        // best-effort only — see the doc above: if the process exits right
        // after this returns, the batch is not exported.
        Ok(_) => {
            tracing::warn!(
                "shutdown_otel() on a current_thread runtime: queued OTLP spans are not \
                 guaranteed to be exported (the batch task shares the single runtime thread); \
                 run on a multi-thread runtime for a flush on exit"
            );
            std::thread::spawn(move || shutdown_provider(&provider));
        }
    }
}

/// Flush and shut down `provider`, ignoring the verdict.
#[cfg(feature = "otel")]
fn shutdown_provider(provider: &opentelemetry_sdk::trace::SdkTracerProvider) {
    // The exit path has nowhere to report a failed export to, and the SDK
    // already logs at debug level; panicking here would replace the process's
    // own exit code with a panic.
    let _ = provider.shutdown();
}

/// No-op when this build has no OTLP exporter, so the daemons can call
/// [`shutdown_otel`] unconditionally.
#[cfg(not(feature = "otel"))]
pub fn shutdown_otel() {}

// `is_token_error(msg) = msg.contains("token") || msg.contains("auth")` used to
// live here; the daemons called it on `e.to_string()` to pick between
// `EXIT_AUTH`/3 and `EXIT_BIND`/4, which let a config *path* choose the exit
// code (`…/authstore.json` → 3, `…/plainstore.json` → 4 for the identical
// malformed-store failure). Classification is now the typed
// `frp_core::init_error::InitErrorKind`, attached where the construction error
// is raised. Do not reintroduce a text classifier here: a message is a
// user-facing string, not a machine channel.

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn is_log_expired_respects_max_days() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let old = now - Duration::from_secs(2 * 24 * 3600);
        let recent = now - Duration::from_secs(12 * 3600);
        // Older than max_days → expired.
        assert!(is_log_expired(old, now, 1));
        // Newer than max_days → not expired.
        assert!(!is_log_expired(recent, now, 1));
        // max_days <= 0 disables cleanup entirely (Go frp semantics).
        assert!(!is_log_expired(old, now, 0));
        assert!(!is_log_expired(old, now, -1));
        // Boundary: exactly max_days old is NOT expired (Go frp uses a strict
        // `mtime < now - maxDays` comparison); one second past the boundary is.
        assert!(!is_log_expired(now - Duration::from_secs(86400), now, 1));
        assert!(is_log_expired(
            now - Duration::from_secs(86400) - Duration::from_secs(1),
            now,
            1
        ));
        // Current/future mtime never expires.
        assert!(!is_log_expired(now, now, 3));
        assert!(!is_log_expired(now + Duration::from_secs(3600), now, 3));
    }

    #[test]
    fn resolve_log_format_precedence_and_fallback() {
        // CLI wins over config.
        assert_eq!(resolve_log_format(Some("json".into()), "text"), "json");
        // Config used when no CLI flag.
        assert_eq!(resolve_log_format(None, "json"), "json");
        assert_eq!(resolve_log_format(None, "text"), "text");
        // Unsupported values fall back to "text".
        assert_eq!(resolve_log_format(Some("yaml".into()), "text"), "text");
        assert_eq!(resolve_log_format(None, "yaml"), "text");
        // Empty string → "text".
        assert_eq!(resolve_log_format(Some("".into()), "text"), "text");
    }

    /// `--log-level ""` is Go's zero value, so it must behave like an absent
    /// flag (Go's `LogConfig.Complete()` fills `""` with `info`,
    /// `pkg/config/v1/common.go:121`), **not** like the literal empty level —
    /// which tracing-core parses as `ERROR`, silencing the pre-fix binaries
    /// while their listeners still came up.
    #[test]
    fn resolve_log_level_treats_empty_cli_value_as_absent() {
        // Empty CLI → the config value.
        assert_eq!(
            resolve_log_level(Some("".into()), Some("warn"), "debug"),
            "warn"
        );
        // Empty CLI with no config value → the built-in default.
        let expected = if cfg!(feature = "debug-logs") {
            "debug"
        } else {
            "info"
        };
        assert_eq!(resolve_log_level(Some("".into()), None, "debug"), expected);
        // A non-empty CLI value still wins.
        assert_eq!(
            resolve_log_level(Some("trace".into()), Some("warn"), "debug"),
            "trace"
        );
        // Nothing set at all.
        assert_eq!(resolve_log_level(None, None, "debug"), expected);
    }

    /// `--log-file ""` is likewise Go's zero value: it must mean "not supplied"
    /// (→ the config destination, `console` by default), not "roll a file at the
    /// empty path". Pre-fix, `Some("")` reached
    /// `tracing_appender::rolling::daily`, whose `file_name()` on an empty path
    /// is `None`, so it silently rolled `frps.log.<date>` in the CWD while both
    /// streams stayed empty.
    #[test]
    fn resolve_log_file_treats_empty_cli_value_as_absent() {
        // Empty CLI → the config destination.
        assert_eq!(resolve_log_file(Some("".into()), "console"), None);
        assert_eq!(resolve_log_file(Some("".into()), ""), None);
        assert_eq!(
            resolve_log_file(Some("".into()), "/var/log/frps.log"),
            Some("/var/log/frps.log".to_string())
        );
        // A non-empty CLI path still wins.
        assert_eq!(
            resolve_log_file(Some("/tmp/x.log".into()), "console"),
            Some("/tmp/x.log".to_string())
        );
        // `console` in the config means stdout.
        assert_eq!(resolve_log_file(None, "console"), None);
    }

    /// `--log-max-days 0` is Go's zero value and means **3**, not "retain
    /// forever": Go completes it with `util.EmptyOr(MaxDays, 3)`
    /// (`pkg/config/v1/common.go:122`). This is the arm the two binaries consume
    /// instead of `cli.log_max_days.or(cfg.log.max_days)`, which let `Some(0)`
    /// beat the `3` that `LogConfig::complete` had just written. The end-to-end
    /// observable (a backdated `logs/frps.log.2020-01-01` surviving startup
    /// cleanup) is pinned by `frps/tests/log_completion.rs`.
    #[test]
    fn resolve_log_max_days_treats_zero_cli_value_as_absent() {
        // The zero CLI value falls through to the config value…
        assert_eq!(resolve_log_max_days(Some(0), Some(5)), 5);
        // …and to the built-in 3 when the config has none.
        assert_eq!(resolve_log_max_days(Some(0), None), 3);
        // The **config** arm is trusted, not filtered: every caller passes a
        // config that `LogConfig::complete` has already filled (0 → 3), so a 0
        // there is a caller that skipped completion, and this resolver does not
        // paper over it. (Only the CLI arm can carry an uncompleted zero.)
        assert_eq!(resolve_log_max_days(Some(0), Some(0)), 0);
        // A non-zero CLI value still wins.
        assert_eq!(resolve_log_max_days(Some(7), Some(5)), 7);
        // A negative CLI value is explicit on Go too — `util.EmptyOr(-1, 3)` is
        // `-1`, which disables cleanup — so only the zero value is filtered.
        assert_eq!(resolve_log_max_days(Some(-1), Some(5)), -1);
        // Nothing set anywhere.
        assert_eq!(resolve_log_max_days(None, None), 3);
        assert_eq!(resolve_log_max_days(None, Some(9)), 9);
    }

    /// `RUST_LOG` outranks the configured level (`filter_from_env`), so the
    /// spawn tests in `frps/tests/log_completion.rs` deliberately clear it —
    /// leaving it set (as `frps/tests/cli_completion.rs` does with
    /// `RUST_LOG=info`) would mask an empty `--log-level`.
    ///
    /// The observable is `Targets::would_enable`, not a byte count: a byte-count
    /// probe of a process-global subscriber is racy, and installing a global
    /// subscriber in a unit test would break every sibling test in this crate.
    #[test]
    fn rust_log_outranks_the_configured_level() {
        // RAII so a panic cannot leave RUST_LOG set for the rest of the process.
        struct RustLogGuard(Option<String>);
        impl Drop for RustLogGuard {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(v) => std::env::set_var("RUST_LOG", v),
                    None => std::env::remove_var("RUST_LOG"),
                }
            }
        }
        let _guard = RustLogGuard(std::env::var("RUST_LOG").ok());

        std::env::remove_var("RUST_LOG");
        assert!(
            filter_from_env("info").would_enable("frp_core", &tracing::Level::INFO),
            "without RUST_LOG the configured level applies"
        );

        std::env::set_var("RUST_LOG", "error");
        assert!(
            !filter_from_env("info").would_enable("frp_core", &tracing::Level::INFO),
            "an explicit RUST_LOG must outrank the configured level"
        );
        assert!(
            filter_from_env("info").would_enable("frp_core", &tracing::Level::ERROR),
            "the RUST_LOG level is what applies, not the configured one"
        );
    }

    #[test]
    fn cleanup_removes_only_expired_prefix_files() {
        let dir = std::env::temp_dir().join(format!("frp_rs_log_cleanup_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // mtime set to 2001-09-09, far older than max_days=1 relative to now.
        let old = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let set_old_mtime = |name: &str| {
            let p = dir.join(name);
            std::fs::write(&p, "x").unwrap();
            std::fs::File::open(&p)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(old))
                .unwrap();
        };

        // Prefix match + old mtime → removed.
        set_old_mtime("frps.log.2020-01-01");
        set_old_mtime("frps.log.2020-01-01.bak");
        // Prefix match + fresh mtime → kept.
        std::fs::write(dir.join("frps.log.2099-01-01"), "x").unwrap();
        // No prefix match → kept even when old.
        set_old_mtime("other.log.2020-01-01");
        // Directory with a matching name → never removed.
        std::fs::create_dir(dir.join("frps.log.2020-01-01.dir")).unwrap();

        let removed = cleanup_expired_logs(&dir, "frps.log", 1);
        assert_eq!(removed, 2);
        assert!(!dir.join("frps.log.2020-01-01").exists());
        assert!(!dir.join("frps.log.2020-01-01.bak").exists());
        assert!(dir.join("frps.log.2099-01-01").exists());
        assert!(dir.join("other.log.2020-01-01").exists());
        assert!(dir.join("frps.log.2020-01-01.dir").exists());

        // max_days <= 0 never removes anything.
        set_old_mtime("frps.log.2019-01-01");
        assert_eq!(cleanup_expired_logs(&dir, "frps.log", 0), 0);
        assert!(dir.join("frps.log.2019-01-01").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_level_maps_known_and_unknown() {
        assert_eq!(parse_level("debug"), LevelFilter::DEBUG);
        assert_eq!(parse_level("trace"), LevelFilter::TRACE);
        assert_eq!(parse_level("off"), LevelFilter::OFF);
        // Unknown → INFO (the safe default).
        assert_eq!(parse_level("bogus"), LevelFilter::INFO);
        // tracing-core 0.1.36 maps "" → **ERROR**, not an error and not INFO
        // (`LevelFilter::from_str`, `metadata.rs:798`). That is the mechanism
        // behind the pre-fix silence for `--log-level ""`: ERROR admits only
        // error records and every startup record is INFO, so both streams were
        // 0 B while the listener still bound. `resolve_log_level` now treats an
        // empty CLI value as absent, so this branch is unreachable from a flag;
        // it stays pinned because it is what made the flag costly.
        assert_eq!(LevelFilter::from_str("").unwrap(), LevelFilter::ERROR);
        assert_eq!(parse_level(""), LevelFilter::ERROR);
    }

    #[test]
    fn targets_from_str_matches_env_filter_static_subset() {
        use tracing::Level;

        // Bare level sets the global default.
        let t: Targets = "info,frp_core=debug".parse().unwrap();
        assert!(t.would_enable("anything", &Level::INFO));
        assert!(t.would_enable("anything", &Level::ERROR));
        assert!(!t.would_enable("anything", &Level::DEBUG));

        // `target=level` enables that target at that level and below (prefix
        // match — `frp_core::x` is a child of `frp_core`).
        assert!(t.would_enable("frp_core", &Level::DEBUG));
        assert!(t.would_enable("frp_core", &Level::INFO));
        assert!(!t.would_enable("frp_core", &Level::TRACE));
        assert!(t.would_enable("frp_core::submodule", &Level::DEBUG));

        // A bare target (no `=`) is enabled at trace.
        let t: Targets = "rustls".parse().unwrap();
        assert!(t.would_enable("rustls", &Level::TRACE));
        assert!(t.would_enable("rustls", &Level::ERROR));
        // With no default, unrelated targets are off.
        assert!(!t.would_enable("other", &Level::ERROR));

        // Multiple directives: more specific target wins over the default.
        let t: Targets = "warn,frp_core=trace".parse().unwrap();
        assert!(!t.would_enable("other", &Level::INFO));
        assert!(t.would_enable("other", &Level::WARN));
        assert!(t.would_enable("frp_core", &Level::TRACE));
    }

    #[test]
    fn targets_from_str_rejects_malformed() {
        // A bad level token fails the whole parse (all-or-nothing) —
        // `filter_from_env` falls back to the default level (and now says so
        // on stderr). A single bad directive drops EVERY valid one too.
        assert!("frp_core=bogus".parse::<Targets>().is_err());
        assert!("info,frp_core=bogus".parse::<Targets>().is_err());
        // Too many `=` in a single directive.
        assert!("a=b=c".parse::<Targets>().is_err());
        // EnvFilter field-VALUE matchers / span scoping always fail here:
        // the token after their last `=` ends in `]` / `}]`, which can never
        // parse as a level (static Targets has no regex engine).
        assert!("foo[bar=baz]".parse::<Targets>().is_err());
        assert!("foo[span{name=x}]".parse::<Targets>().is_err());
        assert!("foo[span{name=x}]=trace".parse::<Targets>().is_err());
    }

    #[test]
    fn targets_from_str_inert_directives_parse_ok() {
        use tracing::Level;

        // `-target` exclusions and `target::*=level` glob suffixes PARSE —
        // no fallback, no error — but become literal target strings that
        // prefix-match nothing real. The directive silently does nothing
        // (EnvFilter would exclude / glob-enable). Pinned so a parser
        // upgrade that starts rejecting or honoring them is a visible
        // change instead of a silent behavior shift.
        let t: Targets = "info,-tokio".parse().unwrap();
        assert!(t.would_enable("anything", &Level::INFO), "default survives");
        // The distinguishing observable: the literal target "-tokio" never
        // matches "tokio", so the GLOBAL DEFAULT still governs it — a real
        // exclusion (EnvFilter semantics) would drop tokio to off here.
        assert!(
            t.would_enable("tokio", &Level::ERROR),
            "inert -tokio must not suppress the default the way a real \
             exclusion would (EnvFilter drops tokio here)"
        );
        let t: Targets = "foo::*=debug".parse().unwrap();
        assert!(
            !t.would_enable("foo::bar", &Level::DEBUG),
            "glob must NOT enable (inert literal), but it enabled foo::bar"
        );
        // Bare numeric token outside the 0-5 level range: a literal target,
        // same as any other bare token that is not a level name.
        let t: Targets = "6".parse().unwrap();
        assert!(!t.would_enable("anything", &Level::TRACE));
    }

    #[test]
    fn targets_from_str_accepts_numeric_levels() {
        use tracing::Level;

        // LevelFilter accepts numeric 0-5 (0 = off, 5 = trace) — the same
        // level parser env-filter uses, so numeric RUST_LOG values are NOT
        // a parse-failure source (doc claim pinned).
        assert!("0".parse::<Targets>().is_ok());
        assert!("3".parse::<Targets>().is_ok());
        assert!("5".parse::<Targets>().is_ok());
        assert!("frp_core=0".parse::<Targets>().is_ok());
        let t: Targets = "frp_core=4".parse().unwrap();
        assert!(t.would_enable("frp_core", &Level::DEBUG));
        assert!(!t.would_enable("frp_core", &Level::TRACE));
    }
}

/// The observable half of [`shutdown_otel`]'s contract, on both supported
/// runtime shapes.
///
/// These tests assert *state and wire output*, not elapsed time. The first cut
/// asserted only "returned in under 2 s", which a `store_otel_provider` that
/// dropped its argument would have satisfied; and because the SDK's `Drop`
/// blocks on the batch task, a regression to a direct wait on a
/// `current_thread` runtime hung the suite (>120 s) instead of failing it. The
/// receive timeouts below are hang guards, not the claim.
#[cfg(all(test, feature = "otel"))]
mod otel_shutdown_tests {
    use super::{build_otel_provider, lock_otel_provider, shutdown_otel, store_otel_provider};
    use opentelemetry::trace::{Span as _, Tracer as _, TracerProvider as _};
    use std::io::{Read as _, Write as _};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// `OTEL_PROVIDER` is process-wide and libtest runs these on separate
    /// threads, so the tests must not interleave.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A socket that accepts the connection and never answers. A *direct*
    /// wait blocks for the exporter's request timeout (10 s by default), so
    /// this is the shape that used to hang instead of fail.
    fn black_hole_endpoint() -> (std::net::TcpListener, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind black-hole sink");
        let endpoint = format!(
            "http://{}/v1/traces",
            listener.local_addr().expect("black-hole local_addr")
        );
        (listener, endpoint)
    }

    /// One-shot OTLP/HTTP sink: accept one connection, read one request, answer
    /// `200`, and report `(head, body)`. Returns the base endpoint (no signal
    /// path) so the normaliser is exercised too.
    fn one_shot_sink() -> (String, mpsc::Receiver<(String, Vec<u8>)>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the sink");
        listener
            .set_nonblocking(true)
            .expect("non-blocking accept on the sink");
        let endpoint = format!("http://{}", listener.local_addr().expect("sink local_addr"));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("sink accept failed: {e}"),
                }
            };
            // The listener is non-blocking only so the accept loop can time
            // out; the accepted socket must block again or `read` returns
            // `WouldBlock` before the exporter's request arrives.
            stream
                .set_nonblocking(false)
                .expect("blocking reads on the accepted sink connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("sink read timeout");
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let head_end = loop {
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
                let n = stream.read(&mut chunk).expect("read the request head");
                assert!(n > 0, "connection closed before the request head ended");
                buf.extend_from_slice(&chunk[..n]);
                assert!(buf.len() < 64 * 1024, "request head too large");
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let content_length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content-length"))
                })
                .expect("the OTLP/HTTP POST must carry content-length");
            while buf.len() < head_end + content_length {
                let n = stream.read(&mut chunk).expect("read the request body");
                assert!(n > 0, "connection closed before the request body ended");
                buf.extend_from_slice(&chunk[..n]);
            }
            let body = buf[head_end..head_end + content_length].to_vec();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .expect("answer the OTLP request");
            tx.send((head, body)).ok();
        });
        (endpoint, rx)
    }

    #[test]
    fn shutdown_otel_empties_the_slot_and_is_idempotent_on_a_current_thread_runtime() {
        let _serial = serial();
        let (_black_hole, endpoint) = black_hole_endpoint();

        // The runtime is entered on a worker thread so the test thread can
        // stop waiting if this regresses into a blocking wait.
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build current_thread runtime");
            let observed = runtime.block_on(async {
                let provider =
                    build_otel_provider(&endpoint, "frp-rs-current-thread-test").expect("build");
                store_otel_provider(Some(provider));
                let stored = lock_otel_provider().is_some();
                shutdown_otel();
                let emptied = lock_otel_provider().is_none();
                // Must not panic: the provider is gone, so this is a no-op.
                shutdown_otel();
                (stored, emptied, lock_otel_provider().is_none())
            });
            tx.send(observed).expect("report the observation");
        });
        let (stored, emptied, stayed_empty) = rx.recv_timeout(Duration::from_secs(10)).expect(
            "shutdown_otel() returned nothing within 10 s on a current_thread runtime: it \
                 must take the provider out and hand it to a detached thread, never wait on the \
                 batch task this runtime owns (that wait deadlocks; the worker's own panic, if \
                 any, is printed above)",
        );
        worker.join().expect("the current_thread worker panicked");
        assert!(stored, "store_otel_provider() must fill OTEL_PROVIDER");
        assert!(
            emptied,
            "shutdown_otel() must take the provider out of OTEL_PROVIDER"
        );
        assert!(
            stayed_empty,
            "a second shutdown_otel() must not install a provider again"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_otel_flushes_on_a_multi_thread_runtime() {
        let _serial = serial();
        let (endpoint, rx) = one_shot_sink();
        let provider =
            build_otel_provider(&endpoint, "frp-rs-multi-thread-test").expect("build provider");
        let tracer = provider.tracer("frp-rs-unit-test");
        store_otel_provider(Some(provider));
        {
            let mut span = tracer.start("otel_export_unit_span");
            span.end();
        }
        shutdown_otel();
        let (head, body) = rx.recv_timeout(Duration::from_secs(10)).expect(
            "shutdown_otel() on a multi-thread runtime exported nothing: the process must own \
             the provider and drain it on the exit path",
        );
        assert!(
            head.starts_with("POST /v1/traces "),
            "the base endpoint must be normalised to /v1/traces, got:\n{head}"
        );
        assert!(
            !body.is_empty(),
            "the exported request body must carry the queued span"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_https_endpoint_does_not_fail_the_provider_build() {
        let _serial = serial();
        // Decision pinned: an endpoint the bundled exporter cannot reach is a
        // loud tracing error, not a startup failure — a daemon that is healthy
        // apart from tracing must still boot. The provider is shut down here so
        // this test leaves the process-wide slot as it found it.
        let provider = build_otel_provider("https://collector.invalid:4318", "frp-rs-https-test")
            .expect("an https endpoint must not turn into a startup failure");
        store_otel_provider(Some(provider));
        shutdown_otel();
        assert!(lock_otel_provider().is_none());
    }
}

/// The endpoint rules from [`normalize_otlp_endpoint`]'s doc block, one test
/// per rule. The integration test in `tests/otel_export_path.rs` proves rule 1
/// on the wire; these pin the shapes it cannot cheaply stand up a sink for.
#[cfg(all(test, feature = "otel"))]
mod otel_endpoint_tests {
    use super::normalize_otlp_endpoint;

    #[test]
    fn bare_base_url_gets_the_signal_path() {
        assert_eq!(
            normalize_otlp_endpoint("http://127.0.0.1:4318"),
            "http://127.0.0.1:4318/v1/traces"
        );
        assert_eq!(
            normalize_otlp_endpoint("https://collector:4318"),
            "https://collector:4318/v1/traces"
        );
    }

    #[test]
    fn lone_slash_counts_as_no_path() {
        assert_eq!(
            normalize_otlp_endpoint("http://127.0.0.1:4318/"),
            "http://127.0.0.1:4318/v1/traces"
        );
    }

    #[test]
    fn an_explicit_path_is_left_alone() {
        assert_eq!(
            normalize_otlp_endpoint("http://127.0.0.1:4318/custom"),
            "http://127.0.0.1:4318/custom"
        );
        // Including one that already carries the signal path: every endpoint
        // that worked before the fix must keep working byte for byte.
        assert_eq!(
            normalize_otlp_endpoint("http://127.0.0.1:4318/v1/traces"),
            "http://127.0.0.1:4318/v1/traces"
        );
        assert_eq!(
            normalize_otlp_endpoint("http://127.0.0.1:4318/v1/traces/"),
            "http://127.0.0.1:4318/v1/traces/"
        );
    }

    #[test]
    fn query_string_is_carried_across() {
        assert_eq!(
            normalize_otlp_endpoint("http://host:4318?x=1"),
            "http://host:4318/v1/traces?x=1"
        );
        assert_eq!(
            normalize_otlp_endpoint("http://host:4318/?x=1"),
            "http://host:4318/v1/traces?x=1"
        );
    }

    #[test]
    fn unparseable_values_stay_verbatim() {
        // The old code passed anything through; it raised no error for a value
        // it could not parse, and this must not start doing so.
        for value in [
            "",
            "   ",
            "collector:4318",
            "127.0.0.1:4318",
            "http://",
            "http:///v1/traces",
            "://collector:4318",
            "1http://collector:4318",
            "not a url at all",
        ] {
            assert_eq!(normalize_otlp_endpoint(value), value, "value {value:?}");
        }
    }
}
