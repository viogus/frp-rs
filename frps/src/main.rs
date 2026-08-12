use std::path::Path;
use std::process;

use frp_core::cli::{parse_frps_args, FrpsArgs};
use frp_core::config::{collect_config_files, load_server_config, ServerConfig};
use frp_core::logging;
use frp_core::unsafe_features::UnsafeFeatures;
use frp_server::service::Service;

#[cfg(all(feature = "mimalloc", not(feature = "mem-profile")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(feature = "mem-profile", not(feature = "mimalloc")))]
#[global_allocator]
static GLOBAL: frp_core::mem_profile::CountingAlloc = frp_core::mem_profile::CountingAlloc;

#[tokio::main]
async fn main() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("fatal: {info}");
    }));
    let cli = parse_frps_args();
    // mem-profile and mimalloc are mutually exclusive (the #[global_allocator]
    // guards are cfg-exclusive): with both enabled neither allocator is
    // installed, so the emitter must not run either.
    #[cfg(all(feature = "mem-profile", not(feature = "mimalloc")))]
    frp_core::mem_profile::spawn_emitter();
    run(cli).await;
}

// ── Logging / tracing init ────────────────────────────────────────────────────

fn init_logging(cli: &FrpsArgs, cfg: Option<&ServerConfig>) {
    let level = logging::resolve_log_level(
        cli.log_level.clone(),
        cfg.map(|c| c.log.level.as_str()),
        "debug",
    );
    let file = logging::resolve_log_file(
        cli.log_file.clone(),
        cfg.map(|c| c.log.file.as_str()).unwrap_or(""),
    );
    let max_days = cli
        .log_max_days
        .or(cfg.map(|c| c.log.max_days))
        .unwrap_or(3);
    let format = logging::resolve_log_format(
        cli.log_format.clone(),
        cfg.map(|c| c.log.format.as_str()).unwrap_or("text"),
    );
    // Go frp v0.70.1 compat: log.disablePrintColor from the config file is
    // honored (audit task 9 finding 9); the CLI --disable-log-color flag
    // takes precedence when both are set.
    let ansi = logging::resolve_ansi(
        cli.disable_log_color || cfg.map(|c| c.log.disable_print_color).unwrap_or(false),
    );
    #[cfg(not(feature = "otel"))]
    logging::init_tracing(&level, file, max_days, &format, ansi, "frps.log");
    #[cfg(feature = "otel")]
    {
        let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .or_else(|| {
                cfg.and_then(|c| {
                    if c.observability.otlp_endpoint.is_empty() {
                        None
                    } else {
                        Some(c.observability.otlp_endpoint.clone())
                    }
                })
            });
        let svc_name = cfg
            .and_then(|c| {
                if c.observability.service_name.is_empty() {
                    None
                } else {
                    Some(c.observability.service_name.clone())
                }
            })
            .unwrap_or_else(|| "frps".to_string());
        logging::init_tracing_otel(
            &level,
            file,
            max_days,
            &format,
            ansi,
            &svc_name,
            otlp_endpoint,
            "frps.log",
        );
    }
}
async fn run(mut cli: FrpsArgs) {
    if cli.show_version {
        println!("frps {}", frp_core::VERSION);
        process::exit(0);
    }

    // Build UnsafeFeatures from CLI --allow-unsafe flag
    let allow_unsafe = std::mem::take(&mut cli.allow_unsafe);
    let refs: Vec<&str> = allow_unsafe.iter().map(|s| s.as_str()).collect();
    let unsafe_features = UnsafeFeatures::new(&refs);

    // Config directory mode: init logging from CLI only
    if let Some(ref dir) = cli.config_dir {
        init_logging(&cli, None);

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
            count = %files.len(),
            "frps (Rust) v{} starting {} services from config directory",
            frp_core::VERSION,
            files.len()
        );
        let mut handles = Vec::new();
        for path in &files {
            let path_str = path.display().to_string();
            // Go frp v0.70.1 parity: with --config-dir each file is
            // authoritative — CLI config flags are not overlaid (audit task
            // 9 finding 5).
            match load_server_config(&path_str, cli.strict_config) {
                Ok(cfg) => {
                    let uf = unsafe_features.clone();
                    handles.push(tokio::spawn(async move {
                        let service = match Service::with_unsafe_features(cfg, Some(path_str.clone()), uf).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::error!(path = %path_str, error = %e, "frps service init failed for [{}]: {}", path_str, e);
                                return;
                            }
                        };
                        if let Err(e) = service.run().await {
                            tracing::error!(path = %path_str, error = %e, "frps service error for config file [{}]: {}", path_str, e);
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
            process::exit(frp_core::EXIT_CONFIG);
        }
        for handle in handles {
            if let Err(e) = handle.await {
                tracing::error!(error = %e, "frps service task panicked: {}", e);
            }
        }
        return;
    }

    // Single config mode: load config first, then init logging with [log] fallback
    let config_path = cli.config_path();
    let mut cfg = match load_server_config(&config_path, cli.strict_config) {
        Ok(cfg) => cfg,
        Err(e) => {
            init_logging(&cli, None);
            tracing::error!(error = %e, "Failed to load config: {}", e);
            process::exit(frp_core::EXIT_CONFIG);
        }
    };

    // Go frp v0.70.1 parity: an explicit `-c` makes the config file
    // authoritative — CLI config flags are ignored (audit task 9 finding 5).
    // Without `-c`, CLI flags override the default frps.toml (frp-rs
    // extension; Go frps would use only flags in that mode).
    if cli.cli_overrides_enabled() {
        cli.override_server_config(&mut cfg);
    }
    init_logging(&cli, Some(&cfg));

    tracing::info!(version = %frp_core::VERSION, "frps (Rust) v{} starting...", frp_core::VERSION);
    let config_path = Some(config_path);
    let service = std::sync::Arc::new(
        Service::with_unsafe_features(cfg, config_path, unsafe_features)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "frps init error: {}", e);
                let code = if logging::is_token_error(&e) {
                    frp_core::EXIT_AUTH
                } else {
                    frp_core::EXIT_BIND
                };
                process::exit(code);
            }),
    );

    // SIGUSR1 reload handler (Unix only) — kill -USR1 <pid>
    #[cfg(unix)]
    let reload_handle = {
        let svc = service.clone();
        tokio::spawn(async move {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()) {
                Ok(mut sig) => {
                    tracing::info!(pid = %std::process::id(), "SIGUSR1 reload ready (pid={})", std::process::id());
                    loop {
                        sig.recv().await;
                        match svc.reload().await {
                            Ok(summary) => {
                                tracing::info!(summary = %summary, "SIGUSR1: {}", summary)
                            }
                            Err(e) => tracing::error!(error = %e, "SIGUSR1 reload: {}", e),
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "SIGUSR1 unavailable: {}", e),
            }
        })
    };

    // SIGUSR2 profiling handler (Unix + profiling) — kill -USR2 <pid>
    // Runs a CPU profile for a configurable duration, writing a flamegraph SVG.
    // Environment variables:
    //   FRP_PROFILE_SECS — profiling duration in seconds (default 30)
    //   FRP_PROFILE_DIR  — output directory (default ".")
    #[cfg(all(unix, feature = "profiling"))]
    let profile_handle = {
        tokio::spawn(async move {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2()) {
                Ok(mut sig) => {
                    tracing::info!(pid = %std::process::id(), "SIGUSR2 profiling ready (pid={})", std::process::id());
                    loop {
                        sig.recv().await;
                        let duration_secs = std::env::var("FRP_PROFILE_SECS")
                            .ok()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(30);
                        let output_dir =
                            std::env::var("FRP_PROFILE_DIR").unwrap_or_else(|_| ".".to_string());
                        tokio::task::spawn_blocking(move || {
                            match frp_core::profiling::dump_cpu_profile(
                                std::time::Duration::from_secs(duration_secs),
                                std::path::Path::new(&output_dir),
                                "frps",
                            ) {
                                Ok(path) => tracing::info!(
                                    "SIGUSR2: CPU profile saved to {}",
                                    path.display()
                                ),
                                Err(e) => {
                                    tracing::error!(error = %e, "SIGUSR2: CPU profile failed: {}", e)
                                }
                            }
                        });
                    }
                }
                Err(e) => tracing::warn!(error = %e, "SIGUSR2 unavailable: {}", e),
            }
        })
    };

    if let Err(e) = service.run().await {
        tracing::error!(error = %e, "frps error: {}", e);
        process::exit(frp_core::EXIT_RUNTIME);
    }

    #[cfg(unix)]
    reload_handle.abort();

    #[cfg(all(unix, feature = "profiling"))]
    profile_handle.abort();
}
