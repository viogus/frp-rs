use std::path::Path;
use std::process;
use std::sync::Arc;

use tokio::signal;
use tracing_subscriber::EnvFilter;

use frp_core::args::{parse_args, CliArgs};
use frp_core::config::{load_client_config, collect_config_files, ClientConfig};
use frp_client::service::Service;

#[tokio::main]
async fn main() {
    let cli = parse_args("frpc.toml", "frpc");
    run(cli).await;
}

fn init_logging(cli: &CliArgs, cfg: Option<&ClientConfig>) {
    // Merge log settings: CLI > config [log] > defaults
    let level = cli.log_level.as_deref().unwrap_or_else(|| {
        cfg.map(|c| c.log.level.as_str()).unwrap_or(
            #[cfg(feature = "debug-logs")]
            "debug,yamux=trace",
            #[cfg(not(feature = "debug-logs"))]
            "info",
        )
    });
    let file = cli.log_file.as_deref().or_else(|| {
        cfg.and_then(|c| if c.log.file.is_empty() { None } else { Some(c.log.file.as_str()) })
    });

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let builder = tracing_subscriber::fmt().with_env_filter(filter);

    if let Some(path) = file {
        let file_appender = tracing_appender::rolling::daily(
            Path::new(path).parent().unwrap_or(Path::new(".")),
            Path::new(path).file_name().unwrap_or(std::ffi::OsStr::new("frpc.log")),
        );
        builder.with_writer(file_appender).init();
    } else {
        builder.init();
    }
}

async fn run(cli: CliArgs) {
    if cli.show_version {
        println!("frpc {}", frp_core::VERSION);
        process::exit(0);
    }

    // Config directory mode: init logging from CLI only
    if let Some(ref dir) = cli.config_dir {
        init_logging(&cli, None);

        let files = match collect_config_files(Path::new(dir)) {
            Ok(files) => files,
            Err(e) => {
                tracing::error!("Failed to read config directory: {}", e);
                process::exit(1);
            }
        };
        if files.is_empty() {
            tracing::error!("No config files found in directory: {dir}");
            process::exit(1);
        }
        tracing::info!(
            "frpc (Rust) v{} starting {} services from config directory",
            frp_core::VERSION,
            files.len()
        );
        let mut handles = Vec::new();
        for path in &files {
            let path_str = path.display().to_string();
            match load_client_config(&path_str) {
                Ok(cfg) => {
                    handles.push(tokio::spawn(async move {
                        let service = match Service::new(cfg, Some(path_str.clone())).await {
                            Ok(svc) => svc,
                            Err(e) => {
                                tracing::error!("frpc service init error for config file [{}]: {}", path_str, e);
                                return;
                            }
                        };
                        if let Err(e) = service.run().await {
                            tracing::error!("frpc service error for config file [{}]: {}", path_str, e);
                        }
                    }));
                }
                Err(e) => {
                    tracing::error!("Failed to load config from [{}]: {}", path_str, e);
                }
            }
        }
        if handles.is_empty() {
            tracing::error!("No services started — all config files failed to load");
            process::exit(1);
        }
        for handle in handles {
            if let Err(e) = handle.await {
                tracing::error!("frpc service task panicked: {}", e);
            }
        }
        return;
    }

    // Single config mode: load config first, then init logging with [log] fallback
    let cfg = match load_client_config(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            init_logging(&cli, None);
            tracing::error!("Failed to load config: {}", e);
            process::exit(1);
        }
    };

    init_logging(&cli, Some(&cfg));

    tracing::info!("frpc (Rust) v{} connecting...", frp_core::VERSION);
    let service = Arc::new(match Service::new(cfg, Some(cli.config.clone())).await {
        Ok(svc) => svc,
        Err(e) => {
            tracing::error!("frpc init error: {}", e);
            process::exit(1);
        }
    });

    // SIGUSR1 → config hot reload
    #[cfg(unix)]
    {
        let reload_svc = service.clone();
        tokio::spawn(async move {
            // SIGUSR1: 30 on macOS, 10 on Linux
            #[cfg(target_os = "macos")]
            const SIGUSR1: std::os::raw::c_int = 30;
            #[cfg(not(target_os = "macos"))]
            const SIGUSR1: std::os::raw::c_int = 10;

            let mut sig = match signal::unix::signal(signal::unix::SignalKind::from_raw(SIGUSR1)) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("SIGUSR1 handler init failed: {}", e);
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
        tracing::error!("frpc error: {}", e);
        process::exit(1);
    }
}
