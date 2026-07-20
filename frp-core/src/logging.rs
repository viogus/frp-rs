//! Shared logging and tracing initialization for frps and frpc binaries.
//!
//! Centralizes the duplicated `resolve_log_settings`, `init_logging`, and
//! `build_otel_layer` functions that were previously copied between
//! `frps/src/main.rs` and `frpc/src/main.rs`.

use std::path::Path;
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
        if cfg_file.is_empty() {
            None
        } else {
            Some(cfg_file.to_string())
        }
    })
}

pub fn resolve_ansi(disable_log_color: bool) -> bool {
    !disable_log_color
}

pub fn init_tracing(level: &str, file: Option<String>, ansi: bool, default_log_name: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(ansi);
    if let Some(path) = file {
        let file_appender = tracing_appender::rolling::daily(
            Path::new(&path).parent().unwrap_or(Path::new(".")),
            Path::new(&path)
                .file_name()
                .unwrap_or(std::ffi::OsStr::new(default_log_name)),
        );
        builder.with_writer(file_appender).init();
    } else {
        builder.init();
    }
}

#[cfg(feature = "otel")]
pub fn init_tracing_otel(
    level: &str,
    file: Option<String>,
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
    if let Some(path) = file {
        let fa = tracing_appender::rolling::daily(
            Path::new(&path).parent().unwrap_or(Path::new(".")),
            Path::new(&path)
                .file_name()
                .unwrap_or(std::ffi::OsStr::new(default_log_name)),
        );
        let reg = tracing_subscriber::registry();
        // Leak the OTel provider so it lives for the process lifetime.
        if let Some(p) = _provider {
            let _ = Box::leak(Box::new(p));
        }
        if let Some(layer) = otel_layer {
            reg.with(layer)
                .with(filter)
                .with(tracing_subscriber::fmt::layer().with_ansi(ansi))
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(fa),
                )
                .init();
        } else {
            reg.with(filter)
                .with(tracing_subscriber::fmt::layer().with_ansi(ansi))
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(fa),
                )
                .init();
        }
    } else {
        let reg = tracing_subscriber::registry();
        // Leak the OTel provider so it lives for the process lifetime.
        if let Some(p) = _provider {
            let _ = Box::leak(Box::new(p));
        }
        if let Some(layer) = otel_layer {
            reg.with(layer)
                .with(filter)
                .with(tracing_subscriber::fmt::layer().with_ansi(ansi))
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
