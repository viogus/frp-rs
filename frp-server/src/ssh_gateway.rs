//! SSH Tunnel Gateway — `ssh -R` reverse tunnel → frp proxy.
//!
//! Users connect with a standard SSH client:
//!   ssh -R :80:127.0.0.1:8080 v0@server -p 2200 tcp --proxy_name "web" --remote_port 9090
//!
//! The remote command string is parsed into a ProxyConfig.

use frp_core::config::ProxyConfig;

/// Parsed result from an SSH remote command string.
#[derive(Debug, PartialEq)]
struct ParsedProxyArgs {
    proxy_type: String,
    proxy_name: String,
    remote_port: u16,
    local_ip: String,
    local_port: u16,
    custom_domains: Vec<String>,
    subdomain: String,
    sk: String,
    multiplexer: String,
    use_encryption: bool,
    use_compression: bool,
    group: String,
    group_key: String,
    http_user: String,
    http_pwd: String,
    host_header_rewrite: String,
    locations: Vec<String>,
    bandwidth_limit: String,
    bandwidth_limit_mode: String,
}

/// Parse SSH remote command args like:
///   "tcp --proxy_name \"web\" --remote_port 9090"
///   "http --proxy_name \"blog\" --custom_domains \"a,b\""
fn parse_ssh_args(cmd: &str) -> Result<ParsedProxyArgs, String> {
    let parts = shell_split(cmd);
    if parts.is_empty() {
        return Err("missing proxy type".into());
    }

    let proxy_type = parts[0].to_lowercase();
    if !VALID_PROXY_TYPES.contains(&proxy_type.as_str()) {
        return Err(format!(
            "unsupported proxy type '{}', supported: {}",
            proxy_type, VALID_PROXY_TYPES.join(", ")
        ));
    }

    let mut args = ParsedProxyArgs {
        proxy_type,
        proxy_name: String::new(),
        remote_port: 0,
        local_ip: String::new(),
        local_port: 0,
        custom_domains: Vec::new(),
        subdomain: String::new(),
        sk: String::new(),
        multiplexer: String::new(),
        use_encryption: false,
        use_compression: false,
        group: String::new(),
        group_key: String::new(),
        http_user: String::new(),
        http_pwd: String::new(),
        host_header_rewrite: String::new(),
        locations: Vec::new(),
        bandwidth_limit: String::new(),
        bandwidth_limit_mode: String::new(),
    };

    let mut i = 1;
    while i < parts.len() {
        match parts[i].as_str() {
            "--proxy_name" => { i += 1; args.proxy_name = parts.get(i).cloned().unwrap_or_default(); }
            "--remote_port" => { i += 1; args.remote_port = parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0); }
            "--local_ip" => { i += 1; args.local_ip = parts.get(i).cloned().unwrap_or_default(); }
            "--local_port" => { i += 1; args.local_port = parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0); }
            "--custom_domains" | "--custom_domain" => { i += 1; args.custom_domains = parts.get(i).map(|s| s.split(',').map(|d| d.trim().to_string()).collect()).unwrap_or_default(); }
            "--subdomain" => { i += 1; args.subdomain = parts.get(i).cloned().unwrap_or_default(); }
            "--sk" => { i += 1; args.sk = parts.get(i).cloned().unwrap_or_default(); }
            "--multiplexer" => { i += 1; args.multiplexer = parts.get(i).cloned().unwrap_or_default(); }
            "--use_encryption" => { i += 1; args.use_encryption = parts.get(i).map(|s| s == "true" || s == "1").unwrap_or(false); }
            "--use_compression" => { i += 1; args.use_compression = parts.get(i).map(|s| s == "true" || s == "1").unwrap_or(false); }
            "--group" => { i += 1; args.group = parts.get(i).cloned().unwrap_or_default(); }
            "--group_key" => { i += 1; args.group_key = parts.get(i).cloned().unwrap_or_default(); }
            "--http_user" => { i += 1; args.http_user = parts.get(i).cloned().unwrap_or_default(); }
            "--http_pwd" => { i += 1; args.http_pwd = parts.get(i).cloned().unwrap_or_default(); }
            "--host_header_rewrite" => { i += 1; args.host_header_rewrite = parts.get(i).cloned().unwrap_or_default(); }
            "--locations" => { i += 1; args.locations = parts.get(i).map(|s| s.split(',').map(|d| d.trim().to_string()).collect()).unwrap_or_default(); }
            "--bandwidth_limit" => { i += 1; args.bandwidth_limit = parts.get(i).cloned().unwrap_or_default(); }
            "--bandwidth_limit_mode" => { i += 1; args.bandwidth_limit_mode = parts.get(i).cloned().unwrap_or_default(); }
            other => {
                // Skip unknown flags or positional args after type
                if !other.starts_with("--") {
                    // positional — ignore (already got the type)
                }
            }
        }
        i += 1;
    }

    Ok(args)
}

const VALID_PROXY_TYPES: &[&str] = &["tcp", "http", "https", "stcp", "tcpmux"];

/// Split a command string into shell-like tokens, respecting double quotes.
fn shell_split(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c == ' ' && !in_quotes {
            if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
        } else {
            current.push(c);
        }
        i += 1;
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_args_tcp() {
        let args = parse_ssh_args(r#"tcp --proxy_name "web" --remote_port 9090"#).unwrap();
        assert_eq!(args.proxy_type, "tcp");
        assert_eq!(args.proxy_name, "web");
        assert_eq!(args.remote_port, 9090);
    }

    #[test]
    fn test_parse_ssh_args_http() {
        let args = parse_ssh_args(r#"http --proxy_name "blog" --custom_domains "a.example.com,b.example.com""#).unwrap();
        assert_eq!(args.proxy_type, "http");
        assert_eq!(args.proxy_name, "blog");
        assert_eq!(args.custom_domains, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn test_parse_ssh_args_unknown_type() {
        let err = parse_ssh_args("smtp --proxy_name test").unwrap_err();
        assert!(err.contains("unsupported proxy type"));
        assert!(err.contains("smtp"));
    }

    #[test]
    fn test_parse_ssh_args_missing_name() {
        let args = parse_ssh_args("tcp --remote_port 9090").unwrap();
        assert!(args.proxy_name.is_empty());
    }

    #[test]
    fn test_parse_ssh_args_stcp() {
        let args = parse_ssh_args(r#"stcp --proxy_name "secret" --sk "mysecret""#).unwrap();
        assert_eq!(args.proxy_type, "stcp");
        assert_eq!(args.sk, "mysecret");
    }

    #[test]
    fn test_parse_ssh_args_tcpmux() {
        let args = parse_ssh_args(r#"tcpmux --proxy_name "mux" --multiplexer "httpconnect""#).unwrap();
        assert_eq!(args.proxy_type, "tcpmux");
        assert_eq!(args.multiplexer, "httpconnect");
    }

    #[test]
    fn test_parse_ssh_args_empty() {
        let err = parse_ssh_args("").unwrap_err();
        assert!(err.contains("missing proxy type"));
    }

    #[test]
    fn test_shell_split_simple() {
        let tokens = shell_split("tcp --proxy_name web --remote_port 9090");
        assert_eq!(tokens, vec!["tcp", "--proxy_name", "web", "--remote_port", "9090"]);
    }

    #[test]
    fn test_shell_split_quoted() {
        let tokens = shell_split(r#"tcp --proxy_name "my web""#);
        assert_eq!(tokens, vec!["tcp", "--proxy_name", "my web"]);
    }
}
