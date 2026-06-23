use std::process;
use std::path::Path;
use std::time::Duration;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use frp_client::service::Service;
use frp_core::config::{load_client_config, collect_config_files};

#[derive(Parser)]
#[command(name = "frpc", about = "frp client (Rust rewrite)")]
struct Cli {
    #[arg(short, long, default_value = "frpc.toml")]
    config: String,

    /// Directory containing config files; one frpc service is started per file
    #[arg(long, conflicts_with = "config")]
    config_dir: Option<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    if let Some(ref dir) = cli.config_dir {
        // --config-dir mode: one independent frpc service per file (matching original frp behavior)
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
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(e) => {
                    tracing::error!("Failed to load config from [{}]: {}", path_str, e);
                }
            }
        }
        for handle in handles {
            let _ = handle.await;
        }
    } else {
        // Single config file mode
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
