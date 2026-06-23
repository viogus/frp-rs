use std::path::Path;
use std::time::Duration;
use std::process;

use tracing_subscriber::EnvFilter;

use frp_core::config::{load_server_config, collect_config_files};
use frp_server::service::Service;

#[tokio::main]
async fn main() {
    let (config, config_dir, cli_log_level, cli_log_file, show_version) = parse_args();

    if show_version {
        println!("frps {}", frp_core::VERSION);
        process::exit(0);
    }

    // Set log level from CLI if provided (overrides RUST_LOG)
    if let Some(ref level) = cli_log_level {
        if std::env::var("RUST_LOG").is_err() {
            std::env::set_var("RUST_LOG", level);
        }
    }

    // Initialize tracing (will use RUST_LOG env var if set)
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            if let Some(ref level) = cli_log_level {
                EnvFilter::new(level)
            } else {
                EnvFilter::new("info")
            }
        });

    let builder = tracing_subscriber::fmt().with_env_filter(filter);

    if let Some(ref file) = cli_log_file {
        // Use a simple rolling file appender
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

    // Rest of the function unchanged
    if let Some(ref dir) = config_dir {
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
            "frps (Rust) v{} starting {} services from config directory",
            frp_core::VERSION,
            files.len()
        );
        let mut handles = Vec::new();
        for path in &files {
            let path_str = path.display().to_string();
            match load_server_config(&path_str) {
                Ok(cfg) => {
                    handles.push(tokio::spawn(async move {
                        let service = Service::new(cfg);
                        if let Err(e) = service.run().await {
                            tracing::error!("frps service error for config file [{}]: {}", path_str, e);
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
        let cfg = match load_server_config(&config) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::error!("Failed to load config: {}", e);
                process::exit(1);
            }
        };
        tracing::info!("frps (Rust) v{} starting...", frp_core::VERSION);
        let service = Service::new(cfg);
        if let Err(e) = service.run().await {
            tracing::error!("frps error: {}", e);
            process::exit(1);
        }
    }
}

fn parse_args() -> (String, Option<String>, Option<String>, Option<String>, bool) {
    let mut args = std::env::args().skip(1).peekable();
    let mut config = "frps.toml".to_string();
    let mut config_dir: Option<String> = None;
    let mut log_file: Option<String> = None;
    let mut log_level: Option<String> = None;
    let mut show_version = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                if let Some(val) = args.next() {
                    config = val;
                } else {
                    eprintln!("error: --config requires a value");
                    process::exit(1);
                }
            }
            "--config-dir" => {
                if let Some(val) = args.next() {
                    config_dir = Some(val);
                } else {
                    eprintln!("error: --config-dir requires a value");
                    process::exit(1);
                }
            }
            "--log-file" => {
                if let Some(val) = args.next() {
                    log_file = Some(val);
                } else {
                    eprintln!("error: --log-file requires a value");
                    process::exit(1);
                }
            }
            "--log-level" => {
                if let Some(val) = args.next() {
                    log_level = Some(val);
                } else {
                    eprintln!("error: --log-level requires a value");
                    process::exit(1);
                }
            }
            "-v" | "--version" => {
                show_version = true;
            }
            "-h" | "--help" => {
                eprintln!("Usage: frps [OPTIONS]");
                eprintln!("");
                eprintln!("Options:");
                eprintln!("  -c, --config <FILE>        Config file path [default: frps.toml]");
                eprintln!("      --config-dir <DIR>     Directory containing config files");
                eprintln!("      --log-file <FILE>      Log file path (appends)");
                eprintln!("      --log-level <LEVEL>    Log level (trace/debug/info/warn/error)");
                eprintln!("  -v, --version              Print version");
                eprintln!("  -h, --help                 Print help");
                process::exit(0);
            }
            _ => {
                eprintln!("error: unknown option `{arg}`");
                process::exit(1);
            }
        }
    }

    (config, config_dir, log_level, log_file, show_version)
}
