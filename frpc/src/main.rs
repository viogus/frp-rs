use std::path::Path;
use std::process;

use tracing_subscriber::EnvFilter;

use frp_core::args::{parse_args, CliArgs};
use frp_core::config::{load_client_config, collect_config_files};
use frp_client::service::Service;

#[tokio::main]
async fn main() {
    let cli = parse_args("frpc.toml", "frpc");
    run(cli).await;
}

async fn run(cli: CliArgs) {
    if cli.show_version {
        println!("frpc {}", frp_core::VERSION);
        process::exit(0);
    }

    // Build EnvFilter: respect RUST_LOG env, fall back to CLI flag, then default
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            EnvFilter::new(cli.log_level.as_deref().unwrap_or("info"))
        });

    let builder = tracing_subscriber::fmt().with_env_filter(filter);

    if let Some(ref file) = cli.log_file {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file)
        {
            Ok(f) => {
                builder.with_writer(std::sync::Mutex::new(f)).init();
            }
            Err(e) => {
                eprintln!("Warning: could not open log file {}: {}. Using stderr.", file, e);
                builder.init();
            }
        }
    } else {
        builder.init();
    }

    // --- Config directory mode ---
    if let Some(ref dir) = cli.config_dir {
        // In config-dir mode, config path is unused
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
                        let service = Service::new(cfg);
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
    } else {
        let cfg = match load_client_config(&cli.config) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::error!("Failed to load config: {}", e);
                process::exit(1);
            }
        };
        tracing::info!("frpc (Rust) v{} connecting...", frp_core::VERSION);
        let service = Service::new(cfg);
        if let Err(e) = service.run().await {
            tracing::error!("frpc error: {}", e);
            process::exit(1);
        }
    }
}
