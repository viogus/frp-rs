use std::path::Path;
use std::process;
use std::sync::Arc;

#[cfg(unix)]
use tokio::signal;
use tracing_subscriber::EnvFilter;

use frp_core::cli::{
    parse_frpc_args, FrpcCmd, FrpcRunArgs,
    build_single_proxy_config,
};
use frp_core::config::{load_client_config, collect_config_files, ClientConfig, ProxyConfig};
use frp_core::{EXIT_AUTH, EXIT_BIND, EXIT_CONFIG, EXIT_RUNTIME};
use frp_client::service::Service;

#[cfg(feature = "mem-profile")]
#[global_allocator]
static GLOBAL: frp_core::mem_profile::CountingAlloc = frp_core::mem_profile::CountingAlloc;

#[tokio::main]
async fn main() {
    let cmd = parse_frpc_args();
    #[cfg(feature = "mem-profile")]
    frp_core::mem_profile::spawn_emitter();
    match cmd {
        FrpcCmd::Run(args) => run_normal(args).await,
        FrpcCmd::Tcp(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Udp(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Http(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Https(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Stcp(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Xtcp(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Sudp(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Tcpmux(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Verify(args) => run_verify(&args.config).await,
    }
}

// ── Logging / tracing init ────────────────────────────────────────────────────

fn resolve_log_settings(_cli: &FrpcRunArgs, cfg: Option<&ClientConfig>) -> (String, Option<String>) {
    let level = cfg.map(|c| c.log.level.as_str()).unwrap_or(
        #[cfg(feature = "debug-logs")]
        "debug,yamux=trace",
        #[cfg(not(feature = "debug-logs"))]
        "info",
    ).to_string();
    let file = cfg.and_then(|c| if c.log.file.is_empty() { None } else { Some(c.log.file.clone()) });
    (level, file)
}

// ── Without `otel` feature: exact current behavior ────────────────────────────

#[cfg(not(feature = "otel"))]
fn init_logging(_cli: &FrpcRunArgs, cfg: Option<&ClientConfig>) {
    let (level, file) = resolve_log_settings(_cli, cfg);
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let builder = tracing_subscriber::fmt().with_env_filter(filter);

    if let Some(path) = file {
        let file_appender = tracing_appender::rolling::daily(
            Path::new(&path).parent().unwrap_or(Path::new(".")),
            Path::new(&path).file_name().unwrap_or(std::ffi::OsStr::new("frpc.log")),
        );
        builder.with_writer(file_appender).init();
    } else {
        builder.init();
    }
}

// ── With `otel` feature: Registry + Layer composition + optional OTLP export ──

#[cfg(feature = "otel")]
fn init_logging(_cli: &FrpcRunArgs, cfg: Option<&ClientConfig>) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let (level, file) = resolve_log_settings(_cli, cfg);

    // OTel endpoint resolution: env var → config field → disabled
    let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .or_else(|| cfg.and_then(|c| {
            if c.observability.otlp_endpoint.is_empty() { None }
            else { Some(c.observability.otlp_endpoint.clone()) }
        }));

    let svc_name = cfg
        .and_then(|c| if c.observability.service_name.is_empty() { None } else { Some(c.observability.service_name.clone()) })
        .unwrap_or_else(|| "frpc".to_string());

    let (otel_layer, _provider) = if let Some(ref ep) = otlp_endpoint {
        match build_otel_layer(ep, &svc_name) {
            Ok((layer, provider)) => (Some(layer), Some(provider)),
            Err(e) => {
                eprintln!("WARNING: OTel init failed (endpoint={ep}): {e}. Tracing without OTLP export.");
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    // Layers created inside each branch to avoid S-type unification.
    if let Some(path) = file {
        let file_appender = tracing_appender::rolling::daily(
            Path::new(&path).parent().unwrap_or(Path::new(".")),
            Path::new(&path).file_name().unwrap_or(std::ffi::OsStr::new("frpc.log")),
        );
        if let Some(layer) = otel_layer {
            if let Some(p) = _provider {
                let _ = Box::leak(Box::new(p));
            }
            tracing_subscriber::registry()
                .with(layer)
                .with(EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new(&level)))
                .with(tracing_subscriber::fmt::layer())
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(file_appender),
                )
                .init();
        } else {
            tracing_subscriber::registry()
                .with(EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new(&level)))
                .with(tracing_subscriber::fmt::layer())
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(file_appender),
                )
                .init();
        }
    } else {
        if let Some(layer) = otel_layer {
            if let Some(p) = _provider {
                let _ = Box::leak(Box::new(p));
            }
            tracing_subscriber::registry()
                .with(layer)
                .with(EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new(&level)))
                .with(tracing_subscriber::fmt::layer())
                .init();
        } else {
            tracing_subscriber::registry()
                .with(EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new(&level)))
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
    }
}

// NOTE: if modifying this function, apply the same changes to frps/src/main.rs
#[cfg(feature = "otel")]
fn build_otel_layer(
    endpoint: &str,
    service_name: &str,
) -> Result<(
    tracing_opentelemetry::OpenTelemetryLayer<
        tracing_subscriber::Registry,
        opentelemetry_sdk::trace::Tracer,
    >,
    opentelemetry_sdk::trace::TracerProvider,
), Box<dyn std::error::Error>> {
    use opentelemetry::KeyValue;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::Resource;
    use opentelemetry_otlp::WithExportConfig as _;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint.to_string())
        .build()?;

    let provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(Resource::new(vec![
            KeyValue::new("service.name", service_name.to_string()),
        ]))
        .build();

    let tracer = provider.tracer("frp-rs");
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);

    Ok((layer, provider))
}

async fn run_normal(args: FrpcRunArgs) {
    if args.show_version {
        println!("frpc {}", frp_core::VERSION);
        process::exit(0);
    }

    // Config directory mode
    if let Some(ref dir) = args.config_dir {
        init_logging(&args, None);

        let files = match collect_config_files(Path::new(dir)) {
            Ok(files) => files,
            Err(e) => {
                tracing::error!(error = %e, "Failed to read config directory: {}", e);
                process::exit(frp_core::EXIT_CONFIG);
            }
        };
        if files.is_empty() {
            tracing::error!(dir = %dir, "No config files found in directory: {dir}");
            process::exit(frp_core::EXIT_CONFIG);
        }
        tracing::info!(
            version = %frp_core::VERSION,
            service_count = %files.len(),
            "frpc (Rust) v{} starting {} services from config directory",
            frp_core::VERSION,
            files.len()
        );
        let mut handles = Vec::new();
        for path in &files {
            let path_str = path.display().to_string();
            match load_client_config(&path_str, args.strict_config) {
                Ok(cfg) => {
                    handles.push(tokio::spawn(async move {
                        let service = match Service::new(cfg, Some(path_str.clone())).await {
                            Ok(svc) => svc,
                            Err(e) => {
                                tracing::error!(config_file = %path_str, error = %e, "frpc service init error for config file [{}]: {}", path_str, e);
                                return;
                            }
                        };
                        if let Err(e) = service.run().await {
                            tracing::error!(config_file = %path_str, error = %e, "frpc service error for config file [{}]: {}", path_str, e);
                        }
                    }));
                }
                Err(e) => {
                    tracing::error!(path = %path_str, error = %e, "Failed to load config from [{}]: {}", path_str, e);
                }
            }
        }
        if handles.is_empty() {
            tracing::error!("No services started — all config files failed to load");
            process::exit(EXIT_CONFIG);
        }
        for handle in handles {
            if let Err(e) = handle.await {
                tracing::error!(error = %e, "frpc service task panicked: {}", e);
            }
        }
        return;
    }

    // Single config mode
    let cfg = match load_client_config(&args.config, args.strict_config) {
        Ok(cfg) => cfg,
        Err(e) => {
            init_logging(&args, None);
            tracing::error!(error = %e, "Failed to load config: {}", e);
            process::exit(EXIT_CONFIG);
        }
    };

    init_logging(&args, Some(&cfg));

    tracing::info!(version = %frp_core::VERSION, "frpc (Rust) v{} connecting...", frp_core::VERSION);
    let service = Arc::new(match Service::new(cfg, Some(args.config.clone())).await {
        Ok(svc) => svc,
        Err(e) => {
            let code = if e.to_string().contains("token") || e.to_string().contains("auth") {
                EXIT_AUTH
            } else {
                EXIT_BIND
            };
            tracing::error!(error = %e, "frpc init error: {}", e);
            process::exit(code);
        }
    });

    // SIGUSR1 → config hot reload
    #[cfg(unix)]
    {
        let reload_svc = service.clone();
        tokio::spawn(async move {
            #[cfg(target_os = "macos")]
            const SIGUSR1: std::os::raw::c_int = 30;
            #[cfg(not(target_os = "macos"))]
            const SIGUSR1: std::os::raw::c_int = 10;

            let mut sig = match signal::unix::signal(signal::unix::SignalKind::from_raw(SIGUSR1)) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "SIGUSR1 handler init failed: {}", e);
                    return;
                }
            };
            loop {
                sig.recv().await;
                reload_svc.request_reload();
            }
        });
    }

    if let Err(e) = service.run().await {
        tracing::error!(error = %e, "frpc error: {}", e);
        process::exit(EXIT_RUNTIME);
    }
}

async fn run_single_proxy(server_addr: &str, server_port: u16, token: Option<&str>, proxy: ProxyConfig) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = build_single_proxy_config(server_addr, server_port, token, proxy);
    tracing::info!(version = %frp_core::VERSION, "frpc (Rust) v{} starting single proxy...", frp_core::VERSION);

    let service = match Service::new(cfg, None).await {
        Ok(svc) => svc,
        Err(e) => {
            let code = if e.to_string().contains("token") || e.to_string().contains("auth") {
                EXIT_AUTH
            } else {
                EXIT_BIND
            };
            tracing::error!(error = %e, "frpc init error: {}", e);
            process::exit(code);
        }
    };

    if let Err(e) = service.run().await {
        tracing::error!(error = %e, "frpc error: {}", e);
        process::exit(EXIT_RUNTIME);
    }
}

async fn run_verify(config_path: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    match load_client_config(config_path, true) {
        Ok(cfg) => {
            println!("Config file {} is valid", config_path);
            println!("  Server: {}:{}", cfg.server_addr, cfg.server_port);
            println!("  Proxies: {}", cfg.proxies.len());
            println!("  Visitors: {}", cfg.visitors.len());
        }
        Err(e) => {
            eprintln!("Config file {} is invalid: {}", config_path, e);
            process::exit(EXIT_CONFIG);
        }
    }
}
