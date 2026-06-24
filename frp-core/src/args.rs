/// Parsed CLI arguments shared by frps and frpc binaries.
#[derive(Debug, Clone)]
pub struct CliArgs {
    pub config: String,
    pub config_dir: Option<String>,
    pub log_level: Option<String>,
    pub log_file: Option<String>,
    pub show_version: bool,
}

/// Parse CLI arguments common to both frps and frpc.
/// `default_config` is the config file name when -c is omitted (e.g. "frps.toml").
/// `bin_name` is used in help text (e.g. "frps").
pub fn parse_args(default_config: &str, bin_name: &str) -> CliArgs {
    let mut args = std::env::args().skip(1).peekable();
    let mut config = default_config.to_string();
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
                    std::process::exit(1);
                }
            }
            "--config-dir" => {
                if let Some(val) = args.next() {
                    config_dir = Some(val);
                } else {
                    eprintln!("error: --config-dir requires a value");
                    std::process::exit(1);
                }
            }
            "--log-file" => {
                if let Some(val) = args.next() {
                    log_file = Some(val);
                } else {
                    eprintln!("error: --log-file requires a value");
                    std::process::exit(1);
                }
            }
            "--log-level" => {
                if let Some(val) = args.next() {
                    log_level = Some(val);
                } else {
                    eprintln!("error: --log-level requires a value");
                    std::process::exit(1);
                }
            }
            "-v" | "--version" => {
                show_version = true;
            }
            "-h" | "--help" => {
                eprintln!("Usage: {bin_name} [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -c, --config <FILE>        Config file path [default: {default_config}]");
                eprintln!("      --config-dir <DIR>     Directory containing config files");
                eprintln!("      --log-file <FILE>      Log file path (appends)");
                eprintln!("      --log-level <LEVEL>    Log level (trace/debug/info/warn/error)");
                eprintln!("  -v, --version              Print version");
                eprintln!("  -h, --help                 Print help");
                std::process::exit(0);
            }
            _ => {
                eprintln!("error: unknown option `{arg}`");
                std::process::exit(1);
            }
        }
    }

    // --config-dir conflicts with an explicit -c/--config value
    if config_dir.is_some() && config != default_config {
        eprintln!("error: --config-dir and --config are mutually exclusive");
        std::process::exit(1);
    }

    CliArgs { config, config_dir, log_level, log_file, show_version }
}
