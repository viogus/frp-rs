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
/// (`frps/src/main.rs:467`). `frpc`'s Go run path binds no `--log-level` flag at
/// all (`Error: unknown flag: --log-level`, rc 1), so the two binaries can be
/// compared on the value they resolve but not on the flag surface.
///
/// **Known open divergence (R1), not parity.** The *non-empty* CLI value on the
/// `-c` lane still does not match Go: on the config above,
/// `frps -c frps.toml --log-level info` prints 11 `INFO` records where Go
/// prints **0**. frp-rs gates only
/// `override_server_config` on `cli_overrides_enabled`
/// (`frps/src/main.rs:986-988`), while `init_logging` (`:991`, defined at `:392`)
/// still reads the raw CLI value. That is pre-existing and is *not* what this
/// function's zero-value filter fixes — the empty-value rows are the ones that
/// now agree.
///
/// Pinned by
/// `frp-core/src/cli.rs::log_flag_zero_values_do_not_override_the_config_file`
/// and
/// `frps/tests/cli_completion.rs::cli_empty_log_level_keeps_the_config_files_level`.
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
        // Leak the OTel provider so it lives for the process lifetime.
        if let Some(p) = _provider {
            let _ = Box::leak(Box::new(p));
        }
        let json = format == "json";
        match (otel_layer, json) {
            (Some(layer), true) => {
                reg.with(layer)
                    .with(filter)
                    .with(tracing_subscriber::fmt::layer().with_ansi(ansi).json())
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
                    .with(tracing_subscriber::fmt::layer().with_ansi(ansi))
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(false)
                            .with_writer(fa),
                    )
                    .init();
            }
            (None, true) => {
                reg.with(filter)
                    .with(tracing_subscriber::fmt::layer().with_ansi(ansi).json())
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
                    .with(tracing_subscriber::fmt::layer().with_ansi(ansi))
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
        // Leak the OTel provider so it lives for the process lifetime.
        if let Some(p) = _provider {
            let _ = Box::leak(Box::new(p));
        }
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
        opentelemetry_sdk::trace::TracerProvider,
    ),
    Box<dyn std::error::Error>,
> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::WithExportConfig as _;
    use opentelemetry_sdk::Resource;
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint.to_string())
        .build()?;
    let provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(Resource::new(vec![KeyValue::new(
            "service.name",
            service_name.to_string(),
        )]))
        .build();
    let tracer = provider.tracer("frp-rs");
    Ok((tracing_opentelemetry::layer().with_tracer(tracer), provider))
}

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
