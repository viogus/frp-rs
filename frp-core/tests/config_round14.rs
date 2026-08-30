//! Round-14 config coverage (test-completeness audit).
//!
//! The round-9..13 additions gave every proxy type a minimal-defaults test
//! and gave udp/sudp/stcp/xtcp/http/https/tcpmux full-sample tests — but
//! never a full-sample TCP proxy (the most common type). This pins the full
//! TCP field set (limits, transport subtable, health check, annotations,
//! metas, groups) in one config, plus Go's lenient unknown-key tolerance.

use frp_core::config::{load_client_config_from_str, ClientConfig};

#[test]
fn test_tcp_proxy_full_sample() {
    let toml = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "tcp-full"
type = "tcp"
localIp = "10.0.0.9"
localPort = 8080
remotePort = 7001
useEncryption = true
useCompression = true
bandwidthLimit = "4MB"
bandwidthLimitMode = "server"
group = "web"
groupKey = "gkey"
allowUsers = ["alice", "bob"]
annotations = { owner = "ops" }
metas = { env = "prod" }
futureField = "ignored"

[proxies.transport]
proxyProtocolVersion = "v2"

[proxies.healthCheck]
type = "http"
url = "http://127.0.0.1/health"
intervalSeconds = 20
timeoutSeconds = 5
maxFailed = 3
httpHeaders = [{ name = "X-Token", value = "abc" }]
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.name, "tcp-full");
    assert_eq!(p.proxy_type, "tcp");
    assert_eq!(p.local_ip, "10.0.0.9");
    assert_eq!(p.local_port, 8080);
    assert_eq!(p.remote_port, 7001);
    assert!(p.use_encryption);
    assert!(p.use_compression);
    assert_eq!(p.bandwidth_limit, "4MB");
    assert_eq!(p.bandwidth_limit_mode, "server");
    assert_eq!(p.group, "web");
    assert_eq!(p.group_key, "gkey");
    assert_eq!(p.allow_users, vec!["alice".to_string(), "bob".to_string()]);
    assert_eq!(p.annotations.get("owner").map(String::as_str), Some("ops"));
    assert_eq!(p.metas.get("env").map(String::as_str), Some("prod"));
    assert_eq!(p.proxy_protocol_version, "v2");
    assert_eq!(p.health_check_type, "http");
    assert_eq!(p.health_check_url, "http://127.0.0.1/health");
    assert_eq!(p.health_check_interval_seconds, 20);
    assert_eq!(p.health_check_timeout_seconds, 5);
    assert_eq!(p.health_check_max_failed, 3);
    assert_eq!(
        p.health_check_http_headers
            .iter()
            .find(|h| h.name == "X-Token")
            .map(|h| h.value.as_str()),
        Some("abc")
    );
    // An unknown key must be tolerated (Go frp parses configs leniently —
    // future Go fields must not break existing frp-rs configs).
    assert!(p.enabled, "enabled default must stay true");
}

#[test]
fn test_tcp_proxy_full_sample_snake_case_keys() {
    // The same proxy expressed with snake_case keys must normalize to the
    // identical ProxyConfig (Go frp accepts both key styles).
    let toml = r#"
server_addr = "127.0.0.1"
server_port = 7000

[[proxies]]
name = "tcp-snake"
type = "tcp"
local_ip = "10.0.0.9"
local_port = 8080
remote_port = 7001
use_encryption = true
bandwidth_limit = "4MB"
bandwidth_limit_mode = "server"

[proxies.transport]
proxy_protocol_version = "v2"

[proxies.healthCheck]
type = "tcp"
intervalSeconds = 15
timeoutSeconds = 3
maxFailed = 2
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.proxy_type, "tcp");
    assert_eq!(p.local_ip, "10.0.0.9");
    assert_eq!(p.remote_port, 7001);
    assert!(p.use_encryption);
    assert_eq!(p.bandwidth_limit, "4MB");
    assert_eq!(p.bandwidth_limit_mode, "server");
    assert_eq!(p.proxy_protocol_version, "v2");
    assert_eq!(p.health_check_type, "tcp");
    assert_eq!(p.health_check_interval_seconds, 15);
    assert_eq!(p.health_check_timeout_seconds, 3);
    assert_eq!(p.health_check_max_failed, 2);
}
