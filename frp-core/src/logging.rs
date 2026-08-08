//! Shared logging and tracing initialization for frps and frpc binaries.
//!
//! Centralizes the duplicated `resolve_log_settings`, `init_logging`, and
//! `build_otel_layer` functions that were previously copied between
//! `frps/src/main.rs` and `frpc/src/main.rs`.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing_subscriber::EnvFilter;

pub fn resolve_log_level(
    cli_level: Option<String>,
    cfg_level: Option<&str>,
    _debug_default: &str,
) -> String {
    cli_level.unwrap_or_else(|| {
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

pub fn resolve_log_file(cli_file: Option<String>, cfg_file: &str) -> Option<String> {
    cli_file.or_else(|| {
        if cfg_file.is_empty() || cfg_file == "console" {
            None // "console" means stdout (Go frp compat)
        } else {
            Some(cfg_file.to_string())
        }
    })
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

pub fn init_tracing(
    level: &str,
    file: Option<String>,
    max_days: i32,
    format: &str,
    ansi: bool,
    default_log_name: &str,
) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    if let Some(path) = file {
        let dir = Path::new(&path).parent().unwrap_or(Path::new("."));
        let log_name = Path::new(&path)
            .file_name()
            .unwrap_or(std::ffi::OsStr::new(default_log_name))
            .to_string_lossy()
            .into_owned();
        let file_appender = tracing_appender::rolling::daily(dir, &log_name);
        if format == "json" {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(ansi)
                .json()
                .with_writer(file_appender)
                .init();
        } else {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(ansi)
                .with_writer(file_appender)
                .init();
        }
        // Startup cleanup + daily cleanup run after the subscriber is live so
        // their warnings are recorded in the log.
        if max_days > 0 {
            cleanup_expired_logs(dir, &log_name, max_days);
            spawn_daily_log_cleanup(dir.to_path_buf(), log_name, max_days);
        }
    } else if format == "json" {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(ansi)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(ansi)
            .init();
    }
}

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
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    // Layer order (innermost → outermost): Registry ← OTel Layer ← EnvFilter ← Fmt Layer
    // OpenTelemetryLayer requires direct Registry, so it must be applied first.
    // fmt::layer() must be constructed inline per branch: dyn Layer is fixed
    // to a single Subscriber type parameter and cannot compose with the
    // Layered<EnvFilter, ...> chain.
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

pub fn is_token_error(msg: &str) -> bool {
    msg.contains("token") || msg.contains("auth")
}

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
}
