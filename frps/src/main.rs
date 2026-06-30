use std::path::Path;
use std::process;

use tracing_subscriber::EnvFilter;

use frp_core::cli::{parse_frps_args, FrpsArgs};
use frp_core::config::{load_server_config, collect_config_files, ServerConfig};
use frp_server::service::Service;

#[tokio::main]
async fn main() {
    let cli = parse_frps_args();
    run(cli).await;
}

fn init_logging(cli: &FrpsArgs, cfg: Option<&ServerConfig>) {
    // Merge log settings: CLI > config [log] > defaults
    let level = cli.log_level.clone().unwrap_or_else(|| {
        cfg.map(|c| c.log.level.as_str()).unwrap_or(
            #[cfg(feature = "debug-logs")]
            "debug",
            #[cfg(not(feature = "debug-logs"))]
            "info",
        ).to_string()
    });
    let file = cli.log_file.clone().or_else(|| {
        cfg.and_then(|c| if c.log.file.is_empty() { None } else { Some(c.log.file.clone()) })
    });

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&level));

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(!cli.disable_log_color);

    if let Some(path) = file {
        let file_appender = tracing_appender::rolling::daily(
            Path::new(&path).parent().unwrap_or(Path::new(".")),
            Path::new(&path).file_name().unwrap_or(std::ffi::OsStr::new("frps.log")),
        );
        builder.with_writer(file_appender).init();
    } else {
        builder.init();
    }
}

async fn run(cli: FrpsArgs) {
    if cli.show_version {
        println!("frps {}", frp_core::VERSION);
        process::exit(0);
    }

    // Config directory mode: init logging from CLI only
    if let Some(ref dir) = cli.config_dir {
        init_logging(&cli, None);

        let files = match collect_config_files(Path::new(dir)) {
            Ok(files) => files,
            Err(e) => {
                tracing::error!(error = %e, "Failed to read config directory: {}", e);
                process::exit(1);
            }
        };
        if files.is_empty() {
            tracing::error!(dir = %dir, "No config files found in directory: {dir}");
            process::exit(1);
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
            match load_server_config(&path_str, cli.strict_config) {
                Ok(mut cfg) => {
                    cli.override_server_config(&mut cfg);
                    handles.push(tokio::spawn(async move {
                        let service = match Service::new(cfg, Some(path_str.clone())).await {
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
            process::exit(1);
        }
        for handle in handles {
            if let Err(e) = handle.await {
                tracing::error!(error = %e, "frps service task panicked: {}", e);
            }
        }
        return;
    }

    // Single config mode: load config first, then init logging with [log] fallback
    let mut cfg = match load_server_config(&cli.config, cli.strict_config) {
        Ok(cfg) => cfg,
        Err(e) => {
            init_logging(&cli, None);
            tracing::error!(error = %e, "Failed to load config: {}", e);
            process::exit(1);
        }
    };

    cli.override_server_config(&mut cfg);
    init_logging(&cli, Some(&cfg));

    tracing::info!(version = %frp_core::VERSION, "frps (Rust) v{} starting...", frp_core::VERSION);
    let config_path = Some(cli.config.clone());
    let service = std::sync::Arc::new(
        Service::new(cfg, config_path).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "frps init error: {}", e);
            process::exit(1);
        })
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
                            Ok(summary) => tracing::info!(summary = %summary, "SIGUSR1: {}", summary),
                            Err(e) => tracing::error!(error = %e, "SIGUSR1 reload: {}", e),
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "SIGUSR1 unavailable: {}", e),
            }
        })
    };

    if let Err(e) = service.run().await {
        tracing::error!(error = %e, "frps error: {}", e);
        process::exit(1);
    }

    #[cfg(unix)]
    reload_handle.abort();
}
