use super::normalize::{expand_env_vars, normalize_client_config, normalize_server_config};
use super::strict::{check_strict, levenshtein};
use super::*;
use crate::feature_gate::VIRTUAL_NET;
use std::io::Write;

#[test]
fn test_parse_client_toml() {
    let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "my-token"

[[proxies]]
name = "test-tcp"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 80
remote_port = 7001
"#;
    let cfg: ClientConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.proxies[0].proxy_type, "tcp");
}

#[test]
fn test_parse_client_store_config() {
    let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000

[store]
path = "./frpc_store.json"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(
        cfg.store.as_ref().unwrap().path,
        "./frpc_store.json",
        "[store] path should be parsed"
    );
}

#[test]
fn test_parse_client_store_defaults_to_none() {
    let cfg: ClientConfig = load_client_config_from_str("server_addr = '127.0.0.1'").unwrap();
    assert!(
        cfg.store.is_none(),
        "store defaults to None without [store]"
    );
}

#[test]
fn test_xtcp_visitor_defaults_to_quic() {
    let visitor = VisitorConfig::default();
    assert_eq!(
        visitor.protocol, "quic",
        "XTCP visitor must default to quic (Go frp v0.70.1)"
    );
}

#[test]
fn test_merge_store_items_overlays_by_name() {
    let base = ClientConfig {
        server_addr: "127.0.0.1".into(),
        proxies: vec![
            ProxyConfig {
                name: "shared".into(),
                proxy_type: "tcp".into(),
                local_port: 1000,
                ..Default::default()
            },
            ProxyConfig {
                name: "config-only".into(),
                proxy_type: "tcp".into(),
                local_port: 2000,
                ..Default::default()
            },
        ],
        visitors: vec![VisitorConfig {
            name: "shared-visitor".into(),
            visitor_type: "stcp".into(),
            bind_port: 3000,
            ..Default::default()
        }],
        ..Default::default()
    };
    let store_proxies = vec![ProxyConfig {
        name: "shared".into(),
        proxy_type: "tcp".into(),
        local_port: 4000,
        enabled: false,
        ..Default::default()
    }];
    let store_visitors = vec![VisitorConfig {
        name: "store-visitor".into(),
        visitor_type: "xtcp".into(),
        bind_port: 5000,
        ..Default::default()
    }];

    let merged = base.merge_store_items(store_proxies, store_visitors);
    let shared = merged.proxies.iter().find(|p| p.name == "shared").unwrap();
    assert_eq!(shared.local_port, 4000, "store entry overlays config entry");
    assert!(
        merged.proxies.iter().any(|p| p.name == "config-only"),
        "config-only proxy is preserved"
    );
    assert!(
        merged.visitors.iter().any(|v| v.name == "store-visitor"),
        "store visitor is added"
    );
}

#[test]
fn test_go_format_server_toml() {
    let toml_str = r#"
[common]
bind_addr = "0.0.0.0"
bind_port = 7000
auth_method = "token"
token = "my-token"
log_file = "./frps.log"
log_level = "info"
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.bind_port, 7000);
    assert_eq!(cfg.auth.token, "my-token");
    assert_eq!(cfg.auth.method, "token");
}

#[test]
fn test_go_camelcase_server_port_aliases() {
    // Go frp uses camelCase: bindPort, kcpBindPort, vhostHTTPPort, etc.
    // These must map to Rust snake_case fields via serde aliases.
    let toml_str = r#"
bindPort = 7000
kcpBindPort = 7100
vhostHTTPPort = 10080
vhostHTTPSPort = 10443
quicBindPort = 7200
sudpPort = 7300
tcpmuxHTTPConnectPort = 7400
websocketPort = 7500
proxyBindAddr = "10.0.0.1"
auth.method = "token"
auth.token = "test"
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.bind_port, 7000, "bindPort");
    #[cfg(feature = "kcp")]
    assert_eq!(cfg.kcp_bind_port, 7100, "kcpBindPort");
    assert_eq!(cfg.vhost_http_port, 10080, "vhostHTTPPort");
    assert_eq!(cfg.vhost_https_port, 10443, "vhostHTTPSPort");
    #[cfg(feature = "quic")]
    assert_eq!(cfg.quic_bind_port, 7200, "quicBindPort");
    assert_eq!(cfg.sudp_port, 7300, "sudpPort");
    assert_eq!(cfg.tcpmux_httpconnect_port, 7400, "tcpmuxHTTPConnectPort");
    #[cfg(feature = "websocket")]
    assert_eq!(cfg.websocket_port, 7500, "websocketPort");
    assert_eq!(cfg.proxy_bind_addr, "10.0.0.1", "proxyBindAddr");
}

#[test]
fn test_go_format_client_with_plugin_toml() {
    let toml_str = r#"
serverAddr = "140.245.66.216"
serverPort = 7000
auth.method = "token"
auth.token = "my-secret-token"

[[proxies]]
name = "home-arm-qb-proxy"
type = "tcp"
remotePort = 10081
[proxies.plugin]
type = "http_proxy"
httpUser = "cdf"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.server_addr, "140.245.66.216");
    assert_eq!(cfg.server_port, 7000);
    assert_eq!(cfg.token, "my-secret-token");
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.proxies[0].name, "home-arm-qb-proxy");
    assert_eq!(cfg.proxies[0].proxy_type, "tcp");
    assert_eq!(cfg.proxies[0].remote_port, 10081);
    let plugin = cfg.proxies[0].plugin.as_ref().unwrap();
    assert_eq!(plugin.plugin_type, "http_proxy");
    assert_eq!(plugin.http_user, "cdf");
}

#[test]
fn test_go_flat_plugin_unix_domain_socket_toml() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "docker_api"
type = "tcp"
remotePort = 9000
plugin = "unix_domain_socket"
plugin_local_addr = "/var/run/docker.sock"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    let plugin = cfg.proxies[0]
        .plugin
        .as_ref()
        .expect("Go-style flat plugin must be parsed");
    assert_eq!(plugin.plugin_type, "unix_domain_socket");
    assert_eq!(plugin.local_addr, "/var/run/docker.sock");
}

#[test]
fn test_go_flat_plugin_http_proxy_fields_toml() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "web_proxy"
type = "tcp"
remotePort = 9001
plugin = "http_proxy"
plugin_http_user = "alice"
plugin_http_password = "secret"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    let plugin = cfg.proxies[0]
        .plugin
        .as_ref()
        .expect("Go-style flat http_proxy plugin must be parsed");
    assert_eq!(plugin.plugin_type, "http_proxy");
    assert_eq!(plugin.http_user, "alice");
    assert_eq!(plugin.http_password, "secret");
}

#[test]
fn test_go_proxy_camelcase_local_fields_toml() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "docker"
type = "tcp"
localIP = "127.0.0.1"
localPort = 2375
remotePort = 6001
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.proxies[0].local_ip, "127.0.0.1");
    assert_eq!(cfg.proxies[0].local_port, 2375);
    assert_eq!(cfg.proxies[0].remote_port, 6001);
}

#[test]
fn test_go_camelcase_server_fields_and_allow_ports() {
    let toml_str = r#"
bindAddr = "0.0.0.0"
bindPort = 7000
subDomainHost = "example.com"
vhostHTTPTimeout = 30
detailedErrorsToClient = false
tcpmuxPassthrough = true
enablePrometheus = true
allowPorts = [{ start = 2000, end = 3000 }, { start = 4000, end = 5000 }]

[webServer]
addr = "127.0.0.1"
port = 7500
user = "admin"
password = "secret"

[auth.oidc]
skipExpiryCheck = true
skipIssuerCheck = true
skipAudience = true
additionalAudience = ["api-prod", "api-staging"]
trustedCaFile = "/etc/ssl/custom-ca.pem"

[[httpPlugins]]
name = "hook"
addr = "http://127.0.0.1:4000"
path = "/handler"
ops = ["login"]

[featureGates]
VirtualNet = true
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.bind_addr, "0.0.0.0");
    assert_eq!(cfg.sub_domain_host, "example.com");
    assert_eq!(cfg.vhost_http_timeout, 30);
    assert!(!cfg.detailed_errors_to_client);
    assert!(cfg.tcp_mux_passthrough);
    assert_eq!(cfg.web_server.port, 7500);
    assert!(cfg.web_server.enable_prometheus);
    assert_eq!(cfg.allow_ports, "2000-3000,4000-5000");
    assert_eq!(cfg.http_plugins.len(), 1);
    assert!(cfg.auth.oidc_skip_expiry);
    assert!(cfg.auth.oidc_skip_issuer);
    assert!(cfg.auth.oidc_skip_audience);
    assert_eq!(
        cfg.auth.oidc_additional_audience,
        vec!["api-prod", "api-staging"]
    );
    assert_eq!(cfg.auth.oidc_tls_trusted_ca_file, "/etc/ssl/custom-ca.pem");
    assert_eq!(cfg.feature.gates.get("VirtualNet"), Some(&true));
}

#[test]
fn test_go_camelcase_client_sections_oidc_visitor_and_plugins() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[transport]
poolCount = 5

[webServer]
port = 7500

[auth.oidc]
clientID = "client-1"
clientSecret = "secret"
tokenEndpointURL = "https://issuer.example.com/token"
scope = "openid"

[featureGates]
VirtualNet = true

[[proxies]]
name = "web"
type = "http"
remotePort = 80
customDomains = ["example.com"]
metadatas = { env = "prod" }
useEncryption = true
useCompression = true
plugin = "unix_domain_socket"
plugin_unix_path = "/var/run/docker.sock"

[[visitors]]
name = "vis"
type = "stcp"
serverName = "s"
bindAddr = "0.0.0.0"
bindPort = 1234
fallbackTimeoutMs = 500

[visitors.transport]
useEncryption = true
useCompression = true

[visitors.natTraversal]
disableAssistedAddrs = true
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.pool_count, 5);
    assert_eq!(cfg.web_server.port, 7500);
    let auth = cfg.auth.as_ref().expect("auth");
    assert_eq!(auth.oidc_client_id, "client-1");
    assert_eq!(auth.oidc_client_secret, "secret");
    assert_eq!(auth.oidc_token_endpoint, "https://issuer.example.com/token");
    assert_eq!(auth.oidc_scope, "openid");
    assert_eq!(cfg.feature.gates.get("VirtualNet"), Some(&true));

    let proxy = &cfg.proxies[0];
    assert_eq!(proxy.custom_domains, vec!["example.com".to_string()]);
    assert_eq!(proxy.metas.get("env").map(String::as_str), Some("prod"));
    assert!(proxy.use_encryption);
    assert!(proxy.use_compression);
    let plugin = proxy.plugin.as_ref().expect("plugin");
    assert_eq!(plugin.plugin_type, "unix_domain_socket");
    assert_eq!(plugin.local_addr, "/var/run/docker.sock");

    let visitor = &cfg.visitors[0];
    assert_eq!(visitor.bind_addr, "0.0.0.0");
    assert_eq!(visitor.bind_port, 1234);
    assert_eq!(visitor.fallback_timeout_ms, 500);
    assert!(visitor.use_encryption);
    assert!(visitor.use_compression);
    assert!(visitor.disable_assisted_addrs);
}

#[test]
fn test_go_virtual_net_client_config() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[featureGates]
VirtualNet = true

[virtualNet]
address = "10.0.0.1"

[[visitors]]
name = "vnet-visitor"
type = "stcp"
serverName = "vnet-server"
secretKey = "secret"
bindPort = -1

[visitors.plugin]
type = "virtual_net"
destinationIP = "100.86.0.1"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.virtual_net.address, "10.0.0.1");
    assert_eq!(cfg.feature.gates.get(VIRTUAL_NET), Some(&true));

    let visitor = &cfg.visitors[0];
    assert_eq!(visitor.bind_port, -1);
    let plugin = visitor.plugin.as_ref().expect("visitor plugin");
    assert_eq!(plugin.plugin_type, "virtual_net");
    assert_eq!(plugin.destination_ip, "100.86.0.1");
}

#[test]
fn test_virtual_net_feature_gate_required() {
    // [virtualNet] without the gate enabled is rejected.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[virtualNet]
address = "10.0.0.1"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("VirtualNet feature is not enabled"), "{err}");

    // virtual_net visitor plugin without the gate enabled is rejected.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[[visitors]]
name = "vnet-visitor"
type = "stcp"
serverName = "vnet-server"
bindPort = -1

[visitors.plugin]
type = "virtual_net"
destinationIP = "100.86.0.1"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("VirtualNet feature is not enabled"), "{err}");
}

#[test]
fn test_virtual_net_visitor_destination_ip_validation() {
    // Missing destinationIP is rejected.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[featureGates]
VirtualNet = true

[[visitors]]
name = "vnet-visitor"
type = "stcp"
serverName = "vnet-server"
bindPort = -1

[visitors.plugin]
type = "virtual_net"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires destinationIP"), "{err}");

    // Invalid IP is rejected.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[featureGates]
VirtualNet = true

[[visitors]]
name = "vnet-visitor"
type = "stcp"
serverName = "vnet-server"
bindPort = -1

[visitors.plugin]
type = "virtual_net"
destinationIP = "not-an-ip"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("invalid destination IP address"), "{err}");
}

#[test]
fn test_virtual_net_proxy_plugin_nested_and_flat_config() {
    let nested = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[featureGates]
VirtualNet = true

[virtualNet]
address = "10.0.0.2"

[[proxies]]
name = "vnet-provider"
type = "tcp"
remotePort = 0

[proxies.plugin]
type = "virtual_net"
"#;
    let cfg: ClientConfig = load_client_config_from_str(nested).unwrap();
    let plugin = cfg.proxies[0]
        .plugin
        .as_ref()
        .expect("nested virtual_net plugin");
    assert_eq!(plugin.plugin_type, "virtual_net");

    let flat = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[featureGates]
VirtualNet = true

[virtualNet]
address = "10.0.0.2"

[[proxies]]
name = "vnet-provider"
type = "tcp"
remotePort = 0
plugin = "virtual_net"
"#;
    let cfg: ClientConfig = load_client_config_from_str(flat).unwrap();
    let plugin = cfg.proxies[0]
        .plugin
        .as_ref()
        .expect("flat virtual_net plugin");
    assert_eq!(plugin.plugin_type, "virtual_net");
}

#[test]
fn test_virtual_net_proxy_plugin_validation() {
    // Feature gate required.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[virtualNet]
address = "10.0.0.2"

[[proxies]]
name = "vnet-provider"
type = "tcp"
plugin = "virtual_net"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("VirtualNet feature is not enabled"), "{err}");

    // [virtualNet] address is required.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[featureGates]
VirtualNet = true

[[proxies]]
name = "vnet-provider"
type = "tcp"
plugin = "virtual_net"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires [virtualNet] address"), "{err}");

    // The plugin is only valid on tcp proxies.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[featureGates]
VirtualNet = true

[virtualNet]
address = "10.0.0.2"

[[proxies]]
name = "vnet-provider"
type = "stcp"
plugin = "virtual_net"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires proxy type tcp"), "{err}");
}

#[test]
fn test_go_extended_server_config_fields() {
    let toml_str = r#"
bindAddr = "127.0.0.1"
bindPort = 7000

[log]
disablePrintColor = true

[webServer]
assetsDir = "/srv/assets"
pprofEnable = true

[webServer.tls]
certFile = "/etc/frps/dash.crt"
keyFile = "/etc/frps/dash.key"

[[httpPlugins]]
name = "hook"
addr = "http://127.0.0.1:4000"
path = "/handler"
ops = ["login"]
tlsVerify = true
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
    assert!(cfg.log.disable_print_color);
    assert_eq!(cfg.web_server.assets_dir, "/srv/assets");
    assert!(cfg.web_server.pprof_enable);
    assert_eq!(cfg.web_server.tls_cert_file, "/etc/frps/dash.crt");
    assert_eq!(cfg.web_server.tls_key_file, "/etc/frps/dash.key");
    assert!(cfg.http_plugins[0].tls_verify);
}

#[test]
fn test_go_extended_proxy_visitor_config_fields() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "web"
type = "http"
remotePort = 80
customDomains = ["web.example.com"]

[proxies.natTraversal]
disableAssistedAddrs = true

[proxies.healthCheck]
type = "http"
url = "http://localhost/health"
httpHeaders = [{ name = "X-Token", value = "abc" }]

[proxies.plugin]
type = "https2http"
crtPath = "/crt"
keyPath = "/key"
enableHTTP2 = true

[proxies.plugin.requestHeaders.set]
X-Custom = "v"

[[visitors]]
name = "vis"
type = "stcp"
serverName = "s"
bindPort = 1234
enabled = false
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    let proxy = &cfg.proxies[0];
    assert!(proxy.disable_assisted_addrs);
    assert_eq!(
        proxy
            .health_check_http_headers
            .iter()
            .find(|h| h.name == "X-Token")
            .map(|h| h.value.as_str()),
        Some("abc")
    );
    let plugin = proxy.plugin.as_ref().expect("plugin");
    assert_eq!(plugin.crt_file, "/crt");
    assert_eq!(plugin.key_file, "/key");
    assert_eq!(plugin.enable_http2, Some(true));
    assert_eq!(
        plugin.request_headers.get("X-Custom").map(String::as_str),
        Some("v")
    );
    assert!(!cfg.visitors[0].enabled);
}

#[test]
fn test_parse_allow_ports() {
    // Empty → empty
    assert!(parse_allow_ports("").unwrap().is_empty());
    // Single range
    assert_eq!(
        parse_allow_ports("10000-20000").unwrap(),
        vec![PortsRange {
            start: 10000,
            end: 20000,
            single: 0
        }]
    );
    // Multiple ranges
    assert_eq!(
        parse_allow_ports("10000-20000,30000-40000").unwrap(),
        vec![
            PortsRange {
                start: 10000,
                end: 20000,
                single: 0
            },
            PortsRange {
                start: 30000,
                end: 40000,
                single: 0
            },
        ]
    );
    // With spaces
    assert_eq!(
        parse_allow_ports("10000-20000, 30000-40000").unwrap(),
        vec![
            PortsRange {
                start: 10000,
                end: 20000,
                single: 0
            },
            PortsRange {
                start: 30000,
                end: 40000,
                single: 0
            },
        ]
    );
    // Reversed range is an error, matching Go's ParseRangeNumbers
    // ("range number is invalid") — audit task 9 finding 7.
    let err = parse_allow_ports("20000-10000").unwrap_err();
    assert!(err.contains("range number is invalid"), "got: {err}");
    // Single port
    assert_eq!(
        parse_allow_ports("8080").unwrap(),
        vec![PortsRange {
            start: 8080,
            end: 8080,
            single: 0
        }]
    );
    // Go `{single=N}` form
    assert_eq!(
        parse_allow_ports("{single=40000}").unwrap(),
        vec![PortsRange {
            start: 40000,
            end: 40000,
            single: 40000
        }]
    );
    assert!(parse_allow_ports("1000-2000,{single=8080}").unwrap()[1].contains(8080));
    assert!(!parse_allow_ports("1000-2000,{single=8080}").unwrap()[1].contains(8081));
    // Mixed
    assert_eq!(
        parse_allow_ports("1000-2000,8080,30000-40000").unwrap(),
        vec![
            PortsRange {
                start: 1000,
                end: 2000,
                single: 0
            },
            PortsRange {
                start: 8080,
                end: 8080,
                single: 0
            },
            PortsRange {
                start: 30000,
                end: 40000,
                single: 0
            },
        ]
    );
    // Invalid entries are config errors (Go validation behavior).
    assert!(parse_allow_ports("not-a-port").is_err());
    assert!(parse_allow_ports("99999").is_err()); // > u16::MAX
    assert!(parse_allow_ports("{single=oops}").is_err());
}

#[test]
fn test_count_ports() {
    assert_eq!(
        count_ports(&[PortsRange {
            start: 10000,
            end: 10009,
            single: 0
        }]),
        10
    );
    assert_eq!(
        count_ports(&[
            PortsRange {
                start: 10000,
                end: 10009,
                single: 0
            },
            PortsRange {
                start: 20000,
                end: 20004,
                single: 0
            },
        ]),
        15
    );
    assert_eq!(
        count_ports(&[PortsRange {
            start: 1,
            end: 1,
            single: 8080
        }]),
        1
    );
    assert_eq!(count_ports(&[]), 0);
}

#[test]
fn test_go_format_client_toml() {
    let toml_str = r#"
[common]
server_addr = "127.0.0.1"
server_port = 7000
token = "my-token"
protocol = "tcp"
pool_count = 1

[[proxies]]
name = "test-tcp"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 80
remote_port = 7001
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.server_port, 7000);
    assert_eq!(cfg.transport_protocol, "tcp");
    assert_eq!(cfg.proxies.len(), 1);
}

#[test]
fn test_parse_allow_ports_edge_cases() {
    // Empty string
    assert!(parse_allow_ports("").unwrap().is_empty());

    // Single port
    let r = parse_allow_ports("8080").unwrap();
    assert_eq!(
        r,
        vec![PortsRange {
            start: 8080,
            end: 8080,
            single: 0
        }]
    );

    // Two single ports
    let r = parse_allow_ports("9000,8000").unwrap();
    assert_eq!(
        r,
        vec![
            PortsRange {
                start: 9000,
                end: 9000,
                single: 0
            },
            PortsRange {
                start: 8000,
                end: 8000,
                single: 0
            },
        ]
    );

    // Mixed ranges and single ports
    let r = parse_allow_ports("1000-2000,3000,5000-6000").unwrap();
    assert_eq!(
        r,
        vec![
            PortsRange {
                start: 1000,
                end: 2000,
                single: 0
            },
            PortsRange {
                start: 3000,
                end: 3000,
                single: 0
            },
            PortsRange {
                start: 5000,
                end: 6000,
                single: 0
            },
        ]
    );

    // Whitespace handling
    let r = parse_allow_ports(" 1000 , 2000-3000 ").unwrap();
    assert_eq!(
        r,
        vec![
            PortsRange {
                start: 1000,
                end: 1000,
                single: 0
            },
            PortsRange {
                start: 2000,
                end: 3000,
                single: 0
            },
        ]
    );

    // Garbage and out-of-range entries are errors (Go validation).
    assert!(parse_allow_ports("not-a-port").is_err());
    assert!(parse_allow_ports("99999").is_err()); // > u16::MAX
    assert!(parse_allow_ports("0").is_err());
}

#[test]
fn test_parse_bandwidth_limit_edge_cases() {
    // Empty → Some(0) (no limit, Go compat)
    assert_eq!(parse_bandwidth_limit(""), Some(0));
    // Bare number without suffix → None (Go requires "KB"/"MB")
    assert_eq!(parse_bandwidth_limit("0"), None);

    // KB variant (binary: 1KB = 1024)
    assert_eq!(parse_bandwidth_limit("1KB"), Some(1024));

    // Single-letter suffix "K" → None (Go requires "KB")
    assert_eq!(parse_bandwidth_limit("1K"), None);

    // MB variant
    assert_eq!(parse_bandwidth_limit("1MB"), Some(1_048_576));

    // Single-letter suffix "M" → None (Go requires "MB")
    assert_eq!(parse_bandwidth_limit("1M"), None);

    // GB variant — Go frp rejects "GB"; must use "MB" or "KB"
    assert_eq!(parse_bandwidth_limit("1GB"), None);

    // Bare number → None (Go requires a suffix)
    assert_eq!(parse_bandwidth_limit("500"), None);

    // Case-SENSITIVE suffix (Go strings.CutSuffix): "mb"/"kb" are rejected.
    assert_eq!(parse_bandwidth_limit("1mb"), None);
    assert_eq!(parse_bandwidth_limit("1kb"), None);
    // 0 / negative number with a valid suffix → Some(0) (no limit, Go
    // NewBandwidthLimiter returns nil for bytes <= 0).
    assert_eq!(parse_bandwidth_limit("0KB"), Some(0));
    assert_eq!(parse_bandwidth_limit("-1MB"), Some(0));

    // Garbage → None
    assert_eq!(parse_bandwidth_limit("not-a-number"), None);
    assert_eq!(parse_bandwidth_limit("abc"), None);

    // Large value doesn't overflow
    assert!(parse_bandwidth_limit("999MB").is_some());
}

#[test]
fn test_auth_client_config_default() {
    let cfg = AuthClientConfig::default();
    assert_eq!(cfg.method, "token");
    assert!(cfg.token.is_empty());
    assert!(cfg.oidc_client_id.is_empty());
    assert!(cfg.oidc_client_secret.is_empty());
    assert!(cfg.oidc_audience.is_empty());
    assert!(cfg.oidc_token_endpoint.is_empty());
    assert!(cfg.oidc_scope.is_empty());
    assert!(cfg.oidc_issuer.is_empty());
    assert!(cfg.additional_endpoint_params.is_empty());
}

#[test]
fn test_parse_server_token_source_file() {
    let toml_str = r#"
bind_port = 7000

[auth.tokenSource]
type = "file"
file.path = "/tmp/frp-token"
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
    let source = cfg.auth.token_source.expect("tokenSource should parse");
    assert_eq!(source.source_type, "file");
    assert_eq!(source.file.unwrap().path, "/tmp/frp-token");
    assert!(source.exec.is_none());
}

#[test]
fn test_parse_client_token_source_exec() {
    let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000

[auth.tokenSource]
type = "exec"
exec.command = "/bin/sh"
exec.args = ["-c", "printf '%s' \"$TOKEN\""]
exec.env = [{ name = "TOKEN", value = "secret" }]
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    let source = cfg
        .auth
        .unwrap()
        .token_source
        .expect("tokenSource should parse");
    assert_eq!(source.source_type, "exec");
    let exec = source.exec.expect("exec source should parse");
    assert_eq!(exec.command, "/bin/sh");
    assert_eq!(exec.args, vec!["-c", "printf '%s' \"$TOKEN\""]);
    assert_eq!(exec.env.len(), 1);
    assert_eq!(exec.env[0].name, "TOKEN");
    assert_eq!(exec.env[0].value, "secret");
}

#[test]
fn test_reject_token_and_token_source_server() {
    let toml_str = r#"
bind_port = 7000

[auth]
token = "static-token"

[auth.tokenSource]
type = "file"
file.path = "/tmp/frp-token"
"#;
    let err = load_server_config_from_str(toml_str)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("cannot specify both auth.token and auth.tokenSource"),
        "{err}"
    );
}

#[test]
fn test_reject_token_and_token_source_client() {
    let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "static-token"

[auth.tokenSource]
type = "file"
file.path = "/tmp/frp-token"
"#;
    let err = load_client_config_from_str(toml_str)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("cannot specify both auth.token and auth.tokenSource"),
        "{err}"
    );
}

#[test]
fn test_reject_unsupported_token_source_type() {
    let toml_str = r#"
bind_port = 7000

[auth.tokenSource]
type = "env"
file.path = "/tmp/frp-token"
"#;
    let err = load_server_config_from_str(toml_str)
        .unwrap_err()
        .to_string();
    assert!(err.contains("unsupported value source type"), "{err}");
}

#[test]
fn test_reject_token_source_missing_file_path() {
    let toml_str = r#"
bind_port = 7000

[auth.tokenSource]
type = "file"
file = {}
"#;
    let err = load_server_config_from_str(toml_str)
        .unwrap_err()
        .to_string();
    assert!(err.contains("file path cannot be empty"), "{err}");
}

#[test]
fn test_client_transport_flatten() {
    // Go frp client config uses [transport] section.
    // normalize_client_config should flatten it to top-level.
    let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "test-token"

[transport]
tcp_mux = false
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    // tcp_mux=false from [transport] should override default (true)
    assert!(!cfg.tcp_mux);
}

#[test]
fn test_client_transport_flatten_default() {
    // Without [transport] section, tcp_mux defaults to true
    let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "test-token"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert!(cfg.tcp_mux);
    // dial_server_keepalive defaults to 7200 (Go frp default) via the serde
    // default fn — a plain `#[serde(default)]` would yield 0 (disabled),
    // silently diverging from the documented default.
    assert_eq!(cfg.dial_server_keepalive, 7200);
    // An explicit 0 still disables.
    let cfg0: ClientConfig = load_client_config_from_str(
        "server_addr = '127.0.0.1'\n[transport]\ndial_server_keepalive = 0",
    )
    .unwrap();
    assert_eq!(cfg0.dial_server_keepalive, 0);
}

#[test]
fn test_tcp_mux_defaults_application_heartbeats_disabled_go_compat() {
    let cfg = load_client_config_from_str("server_addr = '127.0.0.1'").unwrap();

    assert!(cfg.tcp_mux);
    assert_eq!(cfg.heartbeat_interval, -1);
    assert_eq!(cfg.heartbeat_timeout, -1);
}

#[test]
fn test_tcp_mux_preserves_explicit_application_heartbeats() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
heartbeatInterval = 15
heartbeatTimeout = 45
"#,
    )
    .unwrap();

    assert!(cfg.tcp_mux);
    assert_eq!(cfg.heartbeat_interval, 15);
    assert_eq!(cfg.heartbeat_timeout, 45);
}

#[test]
fn test_tcp_mux_disabled_keeps_application_heartbeat_defaults() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
tcpMux = false
"#,
    )
    .unwrap();

    assert!(!cfg.tcp_mux);
    assert_eq!(cfg.heartbeat_interval, default_heartbeat_interval());
    assert_eq!(cfg.heartbeat_timeout, default_heartbeat_timeout());
}

#[test]
fn test_dial_server_timeout_zero_means_default() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
dialServerTimeout = 0
"#,
    )
    .unwrap();

    assert_eq!(cfg.dial_server_timeout, default_dial_server_timeout());
}

#[test]
fn test_go_v0701_server_transport_mux_toml() {
    let cfg = load_server_config_from_str(
        r#"
bindPort = 7000
[transport]
tcpMux = false
tcpMuxKeepaliveInterval = 15
"#,
    )
    .unwrap();

    assert_eq!(cfg.transport.tcp_mux, Some(false));
    assert_eq!(cfg.transport.tcp_mux_keepalive_interval, 15);
}

#[test]
fn test_explicit_server_heartbeat_timeout_90_is_preserved_with_tcp_mux() {
    let cfg = load_server_config_from_str(
        r#"
bindPort = 7000
[transport]
heartbeatTimeout = 90
"#,
    )
    .unwrap();

    assert_eq!(cfg.transport.heartbeat_timeout, 90);
}

#[test]
fn test_explicit_disabled_client_heartbeat_is_preserved() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
heartbeatInterval = -1
heartbeatTimeout = -1
"#,
    )
    .unwrap();

    assert!(cfg.tcp_mux);
    assert_eq!(cfg.heartbeat_interval, -1);
    assert_eq!(cfg.heartbeat_timeout, -1);
}

#[test]
fn test_go_v0701_client_transport_toml() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[transport]
protocol = "quic"
tcpMux = false

[transport.tls]
enable = false
serverName = "frps.example.com"
disableCustomTLSFirstByte = false
"#;
    let cfg = load_client_config_from_str(toml_str).unwrap();

    assert_eq!(cfg.transport_protocol, "quic");
    assert!(!cfg.tcp_mux);
    assert!(!cfg.tls_enable);
    assert_eq!(cfg.tls_server_name, "frps.example.com");
    assert!(!cfg.disable_custom_tls_first_byte);
}

#[test]
fn test_go_v0701_server_transport_tls_toml() {
    let toml_str = r#"
bindPort = 7000

[transport.tls]
force = true
certFile = "/etc/frp/server.crt"
keyFile = "/etc/frp/server.key"
trustedCaFile = "/etc/frp/clients-ca.crt"
serverName = "frps.example.com"
"#;
    let cfg = load_server_config_from_str(toml_str).unwrap();

    assert!(cfg.tls_only);
    assert!(cfg.tls_enable);
    assert_eq!(cfg.tls_cert_file, "/etc/frp/server.crt");
    assert_eq!(cfg.tls_key_file, "/etc/frp/server.key");
    assert_eq!(cfg.tls_ca_file, "/etc/frp/clients-ca.crt");
    assert_eq!(cfg.tls_server_name, "frps.example.com");
}

#[test]
fn test_server_legacy_tls_fields_override_canonical_transport_tls() {
    let toml_str = r#"
tls_enable = false
tls_cert_file = "/legacy/server.crt"
tls_key_file = "/legacy/server.key"
tls_ca_file = "/legacy/clients-ca.crt"

[transport.tls]
force = true
certFile = "/canonical/server.crt"
keyFile = "/canonical/server.key"
trustedCaFile = "/canonical/clients-ca.crt"
serverName = "frps.example.com"
"#;
    let cfg = load_server_config_from_str(toml_str).unwrap();

    assert!(!cfg.tls_enable);
    assert_eq!(cfg.tls_cert_file, "/legacy/server.crt");
    assert_eq!(cfg.tls_key_file, "/legacy/server.key");
    assert_eq!(cfg.tls_ca_file, "/legacy/clients-ca.crt");
    assert!(cfg.tls_only);
    assert_eq!(cfg.tls_server_name, "frps.example.com");
}

#[test]
fn test_server_legacy_tls_only_overrides_canonical_force() {
    let cfg = load_server_config_from_str(
        r#"
tls_only = false

[transport.tls]
force = true
"#,
    )
    .unwrap();

    assert!(!cfg.tls_only);
}

#[test]
fn test_server_canonical_trusted_ca_alone_forces_tls_only_on_complete() {
    let cfg = load_server_config_from_str(
        r#"
[transport.tls]
trustedCaFile = "/etc/frp/clients-ca.crt"
"#,
    )
    .unwrap();

    assert_eq!(cfg.tls_ca_file, "/etc/frp/clients-ca.crt");
    assert!(cfg.tls_only);
}

#[test]
fn test_client_legacy_transport_tls_fields_override_canonical_nested_fields() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
transport_protocol = "tcp"
tcp_mux = true
tls_enable = false
tls_cert_file = "/legacy/client.crt"
tls_key_file = "/legacy/client.key"
tls_ca_file = "/legacy/server-ca.crt"
tls_server_name = "legacy.example.com"
disable_custom_tls_first_byte = true

[transport]
protocol = "quic"
tcpMux = false

[transport.tls]
enable = true
certFile = "/canonical/client.crt"
keyFile = "/canonical/client.key"
trustedCaFile = "/canonical/server-ca.crt"
serverName = "canonical.example.com"
disableCustomTLSFirstByte = false
"#,
    )
    .unwrap();

    assert_eq!(cfg.transport_protocol, "tcp");
    assert!(cfg.tcp_mux);
    assert!(!cfg.tls_enable);
    assert_eq!(cfg.tls_cert_file, "/legacy/client.crt");
    assert_eq!(cfg.tls_key_file, "/legacy/client.key");
    assert_eq!(cfg.tls_ca_file, "/legacy/server-ca.crt");
    assert_eq!(cfg.tls_server_name, "legacy.example.com");
    assert!(cfg.disable_custom_tls_first_byte);
}

#[test]
fn test_strict_mode_accepts_go_v0701_transport_keys() {
    let mut client_file = tempfile::NamedTempFile::new().unwrap();
    client_file
        .write_all(
            br#"serverAddr = "127.0.0.1"
[transport]
protocol = "quic"
tcpMux = false
[transport.tls]
enable = true
serverName = "frps.example.com"
disableCustomTLSFirstByte = false
"#,
        )
        .unwrap();
    load_client_config(client_file.path().to_str().unwrap(), true).unwrap();

    let mut server_file = tempfile::NamedTempFile::new().unwrap();
    server_file
        .write_all(
            br#"bindPort = 7000
[transport]
tcpMux = false
tcpMuxKeepaliveInterval = 30
[transport.tls]
force = true
certFile = "/etc/frp/server.crt"
keyFile = "/etc/frp/server.key"
trustedCaFile = "/etc/frp/clients-ca.crt"
serverName = "frps.example.com"
"#,
        )
        .unwrap();
    load_server_config(server_file.path().to_str().unwrap(), true).unwrap();
}

#[test]
fn test_strict_mode_rejects_transport_and_tls_typos() {
    let mut client_file = tempfile::NamedTempFile::new().unwrap();
    client_file
        .write_all(
            br#"serverAddr = "127.0.0.1"
[transport]
protcol = "quic"
[transport.tls]
enabel = true
"#,
        )
        .unwrap();

    let error = load_client_config(client_file.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(error.contains("protcol"));
    assert!(error.contains("enabel"));
}

#[test]
fn test_oidc_additional_endpoint_params_map() {
    // Go frp v0.70.1: AuthOIDCClientConfig.AdditionalEndpointParams is a
    // map[string]string — TOML table must parse into a HashMap, not a
    // "k=v&k=v" string.
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            auth_method = "oidc"
            [auth]
            method = "oidc"
            [auth.oidc]
            clientID = "client-1"
            tokenEndpointURL = "https://idp.example.com/token"
            additionalEndpointParams = { tenant = "acme", region = "eu" }
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let auth = cfg.auth.expect("auth section");
    assert_eq!(
        auth.additional_endpoint_params
            .get("tenant")
            .map(String::as_str),
        Some("acme")
    );
    assert_eq!(
        auth.additional_endpoint_params
            .get("region")
            .map(String::as_str),
        Some("eu")
    );
}

#[test]
fn test_oidc_token_source_parsed_from_subtable() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            auth_method = "oidc"
            [auth]
            method = "oidc"
            [auth.oidc]
            tokenSource = { type = "file", file = { path = "/tmp/oidc-token" } }
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let auth = cfg.auth.expect("auth section");
    let source = auth
        .oidc_token_source
        .expect("oidc.tokenSource should parse");
    assert_eq!(source.source_type, "file");
    assert_eq!(
        source.file.as_ref().map(|f| f.path.as_str()),
        Some("/tmp/oidc-token")
    );
}

#[test]
fn test_oidc_token_source_mutually_exclusive_with_other_fields() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            auth_method = "oidc"
            [auth]
            method = "oidc"
            [auth.oidc]
            clientID = "client-1"
            tokenSource = { type = "file", file = { path = "/tmp/tok" } }
        "#;
    let err = super::load_client_config_from_str(toml)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("cannot specify both auth.oidc.tokenSource"),
        "expected mutual-exclusivity error, got: {err}"
    );
}

#[test]
fn test_oidc_requires_client_id_and_token_endpoint() {
    // Missing clientID
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            auth_method = "oidc"
            [auth]
            method = "oidc"
            [auth.oidc]
            tokenEndpointURL = "https://idp.example.com/token"
        "#;
    let err = super::load_client_config_from_str(toml)
        .unwrap_err()
        .to_string();
    assert!(err.contains("clientID is required"), "got: {err}");

    // Missing token endpoint (and no issuer for discovery)
    let toml2 = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            auth_method = "oidc"
            [auth]
            method = "oidc"
            [auth.oidc]
            clientID = "client-1"
        "#;
    let err2 = super::load_client_config_from_str(toml2)
        .unwrap_err()
        .to_string();
    assert!(err2.contains("tokenEndpointURL is required"), "got: {err2}");
}

#[test]
fn test_oidc_additional_endpoint_params_scope_rejected() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            auth_method = "oidc"
            [auth]
            method = "oidc"
            [auth.oidc]
            clientID = "client-1"
            tokenEndpointURL = "https://idp.example.com/token"
            additionalEndpointParams = { scope = "openid" }
        "#;
    let err = super::load_client_config_from_str(toml)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("additionalEndpointParams.scope is not allowed"),
        "got: {err}"
    );
}

#[test]
fn test_strict_mode_accepts_server_tls_server_name_alias() {
    let mut server_file = tempfile::NamedTempFile::new().unwrap();
    server_file
        .write_all(
            br#"bindPort = 7000
tlsServerName = "frps.example.com"
"#,
        )
        .unwrap();

    let cfg = load_server_config(server_file.path().to_str().unwrap(), true).unwrap();
    assert_eq!(cfg.tls_server_name, "frps.example.com");
}

#[test]
fn test_client_disable_custom_tls_first_byte_defaults_match_go() {
    assert!(ClientConfig::default().disable_custom_tls_first_byte);

    let cfg: ClientConfig = toml::from_str("server_addr = '127.0.0.1'").unwrap();
    assert!(cfg.disable_custom_tls_first_byte);
}

#[test]
fn test_levenshtein() {
    assert_eq!(levenshtein("server_addr", "serverAddr"), 2); // delete '_' + case change
    assert_eq!(levenshtein("bind_port", "bindPort"), 2); // delete '_' + case change
    assert_eq!(levenshtein("token", "tokens"), 1);
    assert_eq!(levenshtein("abc", "xyz"), 3);
    assert_eq!(levenshtein("", ""), 0);
    assert_eq!(levenshtein("a", ""), 1);
}

#[test]
fn test_unknown_field_suggestion() {
    // Build a simple toml table with an unknown key (flat, no sections)
    let toml_str = "token = \"test\"\nserverAddr = \"1.2.3.4\"\n";
    let value: toml::Value = toml::from_str(toml_str).unwrap();
    let known: std::collections::HashSet<&str> = ["token", "server_addr"].iter().copied().collect();
    let errors = check_strict(value.as_table().unwrap(), &known, "", "test.toml");
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("did you mean 'server_addr'"));
}

#[test]
fn test_auth_client_config_oidc_method() {
    // When method is "oidc", oidc_* fields should be usable
    let cfg = AuthClientConfig {
        method: "oidc".into(),
        oidc_client_id: "client-123".into(),
        oidc_client_secret: "secret-456".into(),
        oidc_audience: "https://api.example.com".into(),
        oidc_issuer: "https://auth.example.com".into(),
        oidc_scope: "openid profile".into(),
        oidc_token_endpoint: "https://auth.example.com/token".into(),
        ..Default::default()
    };
    assert_eq!(cfg.method, "oidc");
    assert_eq!(cfg.oidc_client_id, "client-123");
    assert_eq!(cfg.oidc_audience, "https://api.example.com");
}

#[test]
fn test_ssh_tunnel_gateway_config_snake_case() {
    let toml = r#"
bind_port = 7000

[ssh_tunnel_gateway]
bind_port = 2200
bind_addr = "0.0.0.0"
private_key_file = "/etc/frp/ssh_host_key"
auto_gen_private_key_path = "/var/lib/frp/ssh_key"
authorized_keys_file = "/etc/frp/authorized_keys"
"#;
    let cfg: ServerConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.ssh_tunnel_gateway.bind_port, 2200);
    assert_eq!(cfg.ssh_tunnel_gateway.bind_addr, "0.0.0.0");
    assert_eq!(
        cfg.ssh_tunnel_gateway.private_key_file,
        "/etc/frp/ssh_host_key"
    );
    assert_eq!(
        cfg.ssh_tunnel_gateway.auto_gen_private_key_path,
        "/var/lib/frp/ssh_key"
    );
    assert_eq!(
        cfg.ssh_tunnel_gateway.authorized_keys_file,
        "/etc/frp/authorized_keys"
    );
}

#[test]
fn test_ssh_tunnel_gateway_config_camel_case() {
    let toml = r#"
bindPort = 7000

[sshTunnelGateway]
bindPort = 2200
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.ssh_tunnel_gateway.bind_port, 2200);
}

#[test]
fn test_ssh_tunnel_gateway_default_disabled() {
    let toml = r#"bind_port = 7000"#;
    let cfg: ServerConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.ssh_tunnel_gateway.bind_port, 0);
}

// ─── Property-based tests (proptest) ───────────────────────────────

/// Helper: normalize a TOML string through the full server config pipeline
/// and return the re-serialized TOML (post-normalization).
fn normalize_server_toml(toml_str: &str) -> String {
    let mut val: toml::Value = toml::from_str(toml_str).unwrap();
    normalize_server_config(&mut val);
    toml::to_string(&val).unwrap()
}

/// Helper: normalize a TOML string through the full client config pipeline.
fn normalize_client_toml(toml_str: &str) -> String {
    let mut val: toml::Value = toml::from_str(toml_str).unwrap();
    normalize_client_config(&mut val);
    toml::to_string(&val).unwrap()
}

mod proptest_tests {
    use proptest::prelude::*;

    // ── Strategies ────────────────────────────────────────────────

    /// Generate a valid server TOML config with [common] section.
    fn arb_server_common_config() -> impl Strategy<Value = String> {
        (any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>()).prop_map(
            |(bind_port, vhost_http, vhost_https, dash_port)| {
                format!(
                    "[common]\n\
                         bind_port = {bind_port}\n\
                         vhost_http_port = {vhost_http}\n\
                         vhost_https_port = {vhost_https}\n\
                         web_server_port = {dash_port}\n"
                )
            },
        )
    }

    /// Generate a valid client TOML config with [common] section.
    fn arb_client_common_config() -> impl Strategy<Value = String> {
        (any::<u16>(), "[a-zA-Z0-9._-]{1,16}").prop_map(|(port, addr)| {
            format!(
                "[common]\n\
                     server_addr = \"{addr}\"\n\
                     server_port = {port}\n\
                     token = \"test-token\"\n"
            )
        })
    }

    // ── Server config properties ──────────────────────────────────

    proptest! {
        /// Server config normalization is idempotent: applying it twice
        /// produces the same result as applying it once.
        #[test]
        fn server_normalization_idempotent(toml_str in arb_server_common_config()) {
            let first = super::normalize_server_toml(&toml_str);
            let second = super::normalize_server_toml(&first);
            prop_assert_eq!(first, second,
                "normalize(normalize(x)) != normalize(x)");
        }
    }

    proptest! {
        /// Server config: flat auth fields produce same result as nested [auth].
        #[test]
        fn server_auth_flat_vs_nested_equivalent(
            bind_port in any::<u16>(),
            token in "[a-zA-Z0-9]{4,32}",
        ) {
            let flat = format!(
                "bind_port = {bind_port}\n\
                 auth_method = \"token\"\n\
                 auth_token = \"{token}\"\n"
            );
            let nested = format!(
                "bind_port = {bind_port}\n\
                 [auth]\n\
                 method = \"token\"\n\
                 token = \"{token}\"\n"
            );
            let flat_norm = super::normalize_server_toml(&flat);
            let nested_norm = super::normalize_server_toml(&nested);
            prop_assert_eq!(flat_norm, nested_norm,
                "flat auth fields did not normalize to same result as nested [auth]");
        }
    }

    proptest! {
        /// Server config: flat log fields produce same result as nested [log].
        #[test]
        fn server_log_flat_vs_nested_equivalent(
            bind_port in any::<u16>(),
            level in "trace|debug|info|warn|error",
            file in "[a-z/.]{0,32}",
        ) {
            let flat = format!(
                "bind_port = {bind_port}\n\
                 log_level = \"{level}\"\n\
                 log_file = \"{file}\"\n"
            );
            let nested = format!(
                "bind_port = {bind_port}\n\
                 [log]\n\
                 level = \"{level}\"\n\
                 file = \"{file}\"\n"
            );
            let flat_norm = super::normalize_server_toml(&flat);
            let nested_norm = super::normalize_server_toml(&nested);
            prop_assert_eq!(flat_norm, nested_norm,
                "flat log fields did not normalize to same result as nested [log]");
        }
    }

    proptest! {
        /// Server config: flat web_server fields produce same result as nested [web_server].
        #[test]
        fn server_web_server_flat_vs_nested_equivalent(
            bind_port in any::<u16>(),
            ws_port in any::<u16>(),
            ws_user in "[a-zA-Z0-9]{2,16}",
            ws_pwd in "[a-zA-Z0-9]{2,16}",
        ) {
            let flat = format!(
                "bind_port = {bind_port}\n\
                 web_server_port = {ws_port}\n\
                 web_server_user = \"{ws_user}\"\n\
                 web_server_password = \"{ws_pwd}\"\n"
            );
            let nested = format!(
                "bind_port = {bind_port}\n\
                 [web_server]\n\
                 port = {ws_port}\n\
                 user = \"{ws_user}\"\n\
                 password = \"{ws_pwd}\"\n"
            );
            let flat_norm = super::normalize_server_toml(&flat);
            let nested_norm = super::normalize_server_toml(&nested);
            prop_assert_eq!(flat_norm, nested_norm,
                "flat web_server fields did not normalize to same as nested [web_server]");
        }
    }

    // ── Client config properties ─────────────────────────────────

    proptest! {
        /// Client config normalization is idempotent.
        #[test]
        fn client_normalization_idempotent(toml_str in arb_client_common_config()) {
            let first = super::normalize_client_toml(&toml_str);
            let second = super::normalize_client_toml(&first);
            prop_assert_eq!(first, second,
                "normalize(normalize(x)) != normalize(x)");
        }
    }

    proptest! {
        /// Client config: protocol field maps to transport_protocol.
        #[test]
        fn client_protocol_to_transport_protocol(
            port in any::<u16>(),
            proto in "tcp|kcp|quic|websocket",
            token in "[a-zA-Z0-9]{4,16}",
        ) {
            let input = format!(
                "[common]\n\
                 server_addr = \"127.0.0.1\"\n\
                 server_port = {port}\n\
                 token = \"{token}\"\n\
                 protocol = \"{proto}\"\n"
            );
            let norm = super::normalize_client_toml(&input);
            // After normalization, "protocol" should become "transport_protocol"
            prop_assert!(norm.contains("transport_protocol"),
                "protocol was not normalized to transport_protocol: {norm}");
            prop_assert!(!norm.contains("\nprotocol ="),
                "old protocol key still present after normalization: {norm}");
        }
    }

    proptest! {
        /// Client config: Go camelCase fields normalized to snake_case.
        #[test]
        fn client_camelcase_to_snakecase(
            port in any::<u16>(),
            addr in "[a-z.]{4,16}",
            token in "[a-zA-Z0-9]{4,16}",
        ) {
            let input = format!(
                "[common]\n\
                 serverAddr = \"{addr}\"\n\
                 serverPort = {port}\n\
                 token = \"{token}\"\n"
            );
            let norm = super::normalize_client_toml(&input);
            prop_assert!(norm.contains("server_addr"),
                "serverAddr not normalized to server_addr: {norm}");
            prop_assert!(norm.contains("server_port"),
                "serverPort not normalized to server_port: {norm}");
        }
    }

    proptest! {
        /// Client config: [transport] section flattened to top-level keys.
        #[test]
        fn client_transport_flatten(
            port in any::<u16>(),
            token in "[a-zA-Z0-9]{4,16}",
        ) {
            let input = format!(
                "server_addr = \"127.0.0.1\"\n\
                 server_port = {port}\n\
                 token = \"{token}\"\n\
                 [transport]\n\
                 tcp_mux = false\n"
            );
            let norm = super::normalize_client_toml(&input);
            // After normalization, [transport] should be gone and tcp_mux at top level
            prop_assert!(norm.contains("tcp_mux"),
                "transport.tcp_mux not flattened to top-level: {norm}");
            // The [transport] section itself should be gone
            prop_assert!(!norm.contains("[transport]"),
                "[transport] section still present after flatten: {norm}");
        }
    }

    proptest! {
        /// Server config: [common] section flattened to root, then normalization
        /// is idempotent.
        #[test]
        fn server_common_flatten_idempotent(
            bind_port in any::<u16>(),
            token in "[a-zA-Z0-9]{4,16}",
        ) {
            let input = format!(
                "[common]\n\
                 bind_port = {bind_port}\n\
                 auth_method = \"token\"\n\
                 auth_token = \"{token}\"\n\
                 log_level = \"info\"\n"
            );
            let first = super::normalize_server_toml(&input);
            let second = super::normalize_server_toml(&first);
            prop_assert_eq!(first.clone(), second,
                "[common] flatten + normalize not idempotent");
            // [common] should be gone
            prop_assert!(!first.contains("[common]"),
                "[common] section still present after normalization: {first}");
        }
    }

    // ── Non-proptest edge case tests ─────────────────────────────

    #[test]
    fn server_token_promoted_to_auth() {
        let input = "bind_port = 7000\ntoken = \"my-secret\"\n";
        let norm = super::normalize_server_toml(input);
        assert!(
            norm.contains("[auth]"),
            "token should be promoted into [auth]: {norm}"
        );
        assert!(
            norm.contains("token = \"my-secret\""),
            "token value missing: {norm}"
        );
    }

    #[test]
    fn server_ssh_tunnel_gateway_rename() {
        let input = "bind_port = 7000\n[sshTunnelGateway]\nbindPort = 2200\n";
        let norm = super::normalize_server_toml(input);
        assert!(
            norm.contains("ssh_tunnel_gateway"),
            "sshTunnelGateway not renamed: {norm}"
        );
        assert!(
            !norm.contains("sshTunnelGateway"),
            "old sshTunnelGateway key still present: {norm}"
        );
    }

    #[test]
    fn client_tls_trusted_ca_rename() {
        let input =
            "server_addr = \"x\"\nserver_port = 7000\ntls_trusted_ca_file = \"/certs/ca.pem\"\n";
        let norm = super::normalize_client_toml(input);
        assert!(
            norm.contains("tls_ca_file"),
            "tls_trusted_ca_file not renamed to tls_ca_file: {norm}"
        );
        assert!(
            !norm.contains("tls_trusted_ca_file"),
            "old tls_trusted_ca_file key still present: {norm}"
        );
    }

    #[test]
    fn server_enable_prometheus_to_web_server() {
        let input = "bind_port = 7000\nenable_prometheus = true\n";
        let norm = super::normalize_server_toml(input);
        assert!(
            norm.contains("[web_server]"),
            "enable_prometheus should create [web_server]: {norm}"
        );
        assert!(
            norm.contains("enable_prometheus"),
            "enable_prometheus value missing: {norm}"
        );
    }

    #[test]
    fn client_transport_wire_protocol_v2() {
        let input = "server_addr = \"x\"\nserver_port = 7000\n[transport]\nwireProtocol = \"v2\"\n";
        let norm = super::normalize_client_toml(input);
        assert!(
            norm.contains("v2 = true"),
            "wireProtocol=v2 not converted to v2=true: {norm}"
        );
    }
}

// --- validate_no_duplicate_names tests (Go frp v0.70.0 compat) ---

#[test]
fn duplicate_proxy_names_rejected() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000

            [[proxies]]
            name = "dup"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 22
            remote_port = 6000

            [[proxies]]
            name = "dup"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 3306
            remote_port = 6001
        "#;
    let err = super::load_client_config_from_str(toml).unwrap_err();
    assert!(
        err.to_string().contains("proxy name [dup] is duplicated"),
        "expected duplicate proxy error, got: {err}"
    );
}

#[test]
fn duplicate_visitor_names_rejected() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000

            [[visitors]]
            name = "dup"
            type = "stcp"
            server_name = "a"
            secret_key = "secret"
            bind_port = 9001

            [[visitors]]
            name = "dup"
            type = "stcp"
            server_name = "b"
            secret_key = "secret"
            bind_port = 9002
        "#;
    let err = super::load_client_config_from_str(toml).unwrap_err();
    assert!(
        err.to_string().contains("visitor name [dup] is duplicated"),
        "expected duplicate visitor error, got: {err}"
    );
}

#[test]
fn unique_proxy_names_accepted() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000

            [[proxies]]
            name = "p1"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 22
            remote_port = 6000

            [[proxies]]
            name = "p2"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 3306
            remote_port = 6001
        "#;
    super::load_client_config_from_str(toml).unwrap();
}

#[test]
fn same_name_across_proxy_and_visitor_allowed() {
    // Go frp v0.70.0: proxies and visitors are separate namespaces.
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000

            [[proxies]]
            name = "same"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 22
            remote_port = 6000

            [[visitors]]
            name = "same"
            type = "stcp"
            server_name = "a"
            secret_key = "secret"
            bind_port = 9001
        "#;
    super::load_client_config_from_str(toml).unwrap();
}

// ── HIGH-1 / HIGH-2: Proxy sub-table normalization ────────────────

#[test]
fn proxy_transport_subtable_normalized() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 80
            remote_port = 7001
            [proxies.transport]
            useEncryption = true
            bandwidthLimit = "1MB"
            proxyProtocolVersion = "v2"
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert!(p.use_encryption, "useEncryption should be true");
    assert_eq!(p.bandwidth_limit, "1MB");
    assert_eq!(p.proxy_protocol_version, "v2");
}

#[test]
fn proxy_healthcheck_subtable_normalized() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 80
            remote_port = 7001
            [proxies.healthCheck]
            type = "tcp"
            intervalSeconds = 5
            timeoutSeconds = 2
            maxFailed = 3
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.health_check_type, "tcp");
    assert_eq!(p.health_check_interval_seconds, 5);
    assert_eq!(p.health_check_timeout_seconds, 2);
    assert_eq!(p.health_check_max_failed, 3);
}

#[test]
fn proxy_loadbalancer_subtable_normalized() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 80
            remote_port = 7001
            [proxies.loadBalancer]
            group = "web"
            groupKey = "secret"
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.group, "web");
    assert_eq!(p.group_key, "secret");
}

#[test]
fn proxy_request_headers_set_normalized() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "http"
            local_ip = "127.0.0.1"
            local_port = 80
            custom_domains = ["example.com"]
            [proxies.requestHeaders.set]
            "x-from-where" = "value"
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(
        p.headers.get("x-from-where").map(|s| s.as_str()),
        Some("value")
    );
}

#[test]
fn proxy_response_headers_set_normalized() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "http"
            local_ip = "127.0.0.1"
            local_port = 80
            custom_domains = ["example.com"]
            [proxies.responseHeaders.set]
            "X-Frame-Options" = "DENY"
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(
        p.response_headers
            .get("X-Frame-Options")
            .map(|s| s.as_str()),
        Some("DENY")
    );
}

// ── MEDIUM-3: LogConfig `to` alias ─────────────────────────────────

#[test]
fn log_to_alias_works() {
    let toml = "level = \"debug\"\nto = \"/var/log/frps.log\"\nmax_days = 7\n";
    let cfg: super::LogConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.file, "/var/log/frps.log");
}

// ── MEDIUM-3b: LogConfig `format` field ────────────────────────────

#[test]
fn log_format_defaults_to_text() {
    let cfg = super::LogConfig::default();
    assert_eq!(cfg.format, "text");
}

#[test]
fn log_format_parses_json() {
    let toml = "level = \"info\"\nformat = \"json\"\nmax_days = 0\n";
    let cfg: super::LogConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.format, "json");
}

#[test]
fn log_format_preserved_when_absent() {
    // A config without `format` must still deserialize (serde default).
    let toml = "level = \"debug\"\n";
    let cfg: super::LogConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.format, "text");
}

// ── MEDIUM-4: WebServer addr default ────────────────────────────────

#[test]
fn web_server_addr_defaults_to_localhost() {
    let cfg = super::WebServerConfig::default();
    assert_eq!(cfg.addr, "127.0.0.1");
}

// ── MEDIUM-5: OIDC nesting normalization ───────────────────────────

#[test]
fn auth_oidc_subtable_normalized() {
    let toml = r#"
bind_port = 7000
[auth.oidc]
issuer = "https://auth.example.com"
audience = "https://api.example.com"
tokenEndpointURL = "https://auth.example.com/token"
"#;
    let cfg: super::ServerConfig = super::load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.auth.oidc_issuer, "https://auth.example.com");
    assert_eq!(cfg.auth.oidc_audience, "https://api.example.com");
    assert_eq!(
        cfg.auth.oidc_token_endpoint,
        "https://auth.example.com/token"
    );
}

// ── MEDIUM-6: HTTP plugins addr+path normalization ─────────────────

#[test]
fn http_plugin_addr_path_to_url() {
    let toml = r#"
bind_port = 7000
[[http_plugins]]
name = "test"
addr = "http://127.0.0.1:4000"
path = "/handler"
"#;
    let cfg: super::ServerConfig = super::load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.http_plugins[0].addr, "http://127.0.0.1:4000");
    assert_eq!(cfg.http_plugins[0].path, "/handler");
}

// ── MEDIUM-8: custom_404_page normalization ────────────────────────

#[test]
fn custom_404_page_top_level_normalized() {
    let toml = r#"
bind_port = 7000
custom404Page = "<html>Not Found</html>"
"#;
    let cfg: super::ServerConfig = super::load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.web_server.custom_404_page, "<html>Not Found</html>");
}

// ── MEDIUM-9: transport legacy fields normalization ─────────────────

#[test]
fn transport_legacy_fields_normalized() {
    let toml = r#"
bind_port = 7000
heartbeat_timeout = 120
max_pool_count = 10
"#;
    let cfg: super::ServerConfig = super::load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.transport.heartbeat_timeout, 120);
    assert_eq!(cfg.transport.max_pool_count, 10);
}

// ─── YAML config support (Go frp v0.70.1 Viper parity) ──────────────

/// Parse a YAML server config through the full pipeline (YAML → toml::Value
/// → normalize → deserialize), mirroring `load_server_config_from_str` for
/// TOML.
fn load_server_config_from_yaml(yaml: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut value = super::format::parse_to_toml_value(yaml, super::format::ConfigFormat::Yaml)?;
    expand_env_vars(&mut value);
    normalize_server_config(&mut value);
    let presence = super::loader::ConfigPresence::from_normalized_value(&value);
    let json_value = super::normalize::toml_to_json(value);
    let mut cfg: ServerConfig =
        serde_json::from_value(json_value).map_err(|e| format!("config validation error: {e}"))?;
    super::loader::validate_server_config(&cfg)?;
    cfg.transport
        .complete_with_heartbeat_timeout_set(presence.server_heartbeat_timeout_set);
    cfg.complete();
    Ok(cfg)
}

/// Parse a YAML client config through the full pipeline, mirroring
/// `load_client_config_from_str` for TOML.
fn load_client_config_from_yaml(yaml: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut value = super::format::parse_to_toml_value(yaml, super::format::ConfigFormat::Yaml)?;
    expand_env_vars(&mut value);
    normalize_client_config(&mut value);
    let presence = super::loader::ConfigPresence::from_normalized_value(&value);
    let mut cfg: ClientConfig = serde_json::from_value(super::normalize::toml_to_json(value))
        .map_err(|e| format!("config validation error: {e}"))?;
    super::loader::validate_client_config(&cfg)?;
    cfg.complete_with_heartbeat_set(
        presence.client_heartbeat_interval_set,
        presence.client_heartbeat_timeout_set,
    );
    Ok(cfg)
}

#[test]
fn test_detect_format_yaml_extensions() {
    use super::format::{detect_format, ConfigFormat};
    assert_eq!(detect_format("frps.yaml"), ConfigFormat::Yaml);
    assert_eq!(detect_format("frpc.yml"), ConfigFormat::Yaml);
    assert_eq!(
        detect_format("frps.YAML"),
        ConfigFormat::Yaml,
        "case-insensitive"
    );
    assert_eq!(detect_format("frps.toml"), ConfigFormat::Toml);
}

#[test]
fn test_server_yaml_equivalent_to_toml() {
    let toml = r#"
bind_addr = "0.0.0.0"
bind_port = 7000

[auth]
method = "token"
token = "my-token"

[log]
level = "info"
"#;
    let yaml = r#"
bind_addr: "0.0.0.0"
bind_port: 7000
auth:
  method: token
  token: my-token
log:
  level: info
"#;
    let toml_cfg = super::load_server_config_from_str(toml).unwrap();
    let yaml_cfg = load_server_config_from_yaml(yaml).unwrap();
    assert_eq!(toml_cfg.bind_addr, yaml_cfg.bind_addr);
    assert_eq!(toml_cfg.bind_port, yaml_cfg.bind_port);
    assert_eq!(toml_cfg.auth.method, yaml_cfg.auth.method);
    assert_eq!(toml_cfg.auth.token, yaml_cfg.auth.token);
    assert_eq!(toml_cfg.log.level, yaml_cfg.log.level);
}

#[test]
fn test_client_yaml_equivalent_to_toml() {
    let toml = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "client-token"

[[proxies]]
name = "web"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 8080
remote_port = 7001
"#;
    let yaml = r#"
server_addr: "127.0.0.1"
server_port: 7000
token: client-token
proxies:
  - name: web
    type: tcp
    local_ip: "127.0.0.1"
    local_port: 8080
    remote_port: 7001
"#;
    let toml_cfg = super::load_client_config_from_str(toml).unwrap();
    let yaml_cfg = load_client_config_from_yaml(yaml).unwrap();
    assert_eq!(toml_cfg.server_addr, yaml_cfg.server_addr);
    assert_eq!(toml_cfg.server_port, yaml_cfg.server_port);
    assert_eq!(toml_cfg.token, yaml_cfg.token);
    assert_eq!(toml_cfg.proxies.len(), yaml_cfg.proxies.len());
    let (tp, yp) = (&toml_cfg.proxies[0], &yaml_cfg.proxies[0]);
    assert_eq!(tp.name, yp.name);
    assert_eq!(tp.proxy_type, yp.proxy_type);
    assert_eq!(tp.local_ip, yp.local_ip);
    assert_eq!(tp.local_port, yp.local_port);
    assert_eq!(tp.remote_port, yp.remote_port);
}

#[test]
fn test_yaml_merge_key_applied_at_parse_time() {
    let yaml = r#"
defaults: &defaults
  a: 1
  b: 2
merged:
  <<: *defaults
  b: 3
"#;
    let value =
        super::format::parse_to_toml_value(yaml, super::format::ConfigFormat::Yaml).unwrap();
    let merged = value.get("merged").expect("merged table");
    assert_eq!(
        merged.get("a").and_then(toml::Value::as_integer),
        Some(1),
        "inherited key from <<"
    );
    assert_eq!(
        merged.get("b").and_then(toml::Value::as_integer),
        Some(3),
        "explicit key wins over merge"
    );
    assert!(merged.get("<<").is_none(), "merge key must be consumed");
}

#[test]
fn test_yaml_merge_key_merges_anchor_fields() {
    let yaml = r#"
server_addr: "127.0.0.1"
server_port: 7000
proxies:
  - &base
    name: base
    type: tcp
    local_ip: "127.0.0.1"
    use_encryption: true
  - <<: *base
    name: merged
    local_port: 8080
    remote_port: 7001
"#;
    let cfg = load_client_config_from_yaml(yaml).unwrap();
    assert_eq!(cfg.proxies.len(), 2);
    let merged = cfg.proxies.iter().find(|p| p.name == "merged").unwrap();
    assert_eq!(merged.local_ip, "127.0.0.1", "<< merged local_ip");
    assert!(merged.use_encryption, "<< merged use_encryption");
    assert_eq!(merged.local_port, 8080, "explicit field wins over merge");
    assert_eq!(merged.remote_port, 7001);
}

#[test]
fn test_yaml_include_file_merged() {
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("frps.toml");
    std::fs::write(
        &main_path,
        r#"
bind_addr = "0.0.0.0"
bind_port = 7000
includes = ["extra.yaml"]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("extra.yaml"),
        r#"
auth:
  method: token
  token: "yaml-token"
"#,
    )
    .unwrap();
    let cfg = super::load_server_config(main_path.to_str().unwrap(), false).unwrap();
    assert_eq!(cfg.bind_addr, "0.0.0.0");
    assert_eq!(cfg.bind_port, 7000);
    assert_eq!(cfg.auth.method, "token");
    assert_eq!(
        cfg.auth.token, "yaml-token",
        "include .yaml should merge auth.token"
    );
}

#[test]
fn test_collect_config_files_includes_yaml_and_yml() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "a.toml",
        "b.yaml",
        "c.yml",
        "d.json",
        "notes.txt",
        "CONFIG.YAML",
    ] {
        std::fs::write(dir.path().join(name), "").unwrap();
    }
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub").join("e.yaml"), "").unwrap();
    std::fs::write(dir.path().join("sub").join("f.ini"), "").unwrap();
    let files = super::collect_config_files(dir.path()).unwrap();
    let names: Vec<String> = files
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    for expected in [
        "a.toml",
        "b.yaml",
        "c.yml",
        "d.json",
        "e.yaml",
        "f.ini",
        "CONFIG.YAML",
    ] {
        assert!(
            names.contains(&expected.to_string()),
            "missing {expected}: {names:?}"
        );
    }
    assert!(
        !names.iter().any(|n| n == "notes.txt"),
        "non-config file collected: {names:?}"
    );
}

// ─── Env var expansion (Go frp Viper `${ENV_VAR}` parity) ───────────
//
// All variable names use the unique `FRP_RS_TEST_ENV_` prefix. Tests run in
// parallel in one process, so each test touches only its own variable name.

#[test]
fn test_env_var_expansion_basic() {
    std::env::set_var("FRP_RS_TEST_ENV_SERVER", "10.0.0.1");
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "${FRP_RS_TEST_ENV_SERVER}"
server_port = 7000
token = "pre-${FRP_RS_TEST_ENV_SERVER}-post"
"#,
    )
    .unwrap();
    std::env::remove_var("FRP_RS_TEST_ENV_SERVER");
    assert_eq!(cfg.server_addr, "10.0.0.1", "basic ${{VAR}} expansion");
    assert_eq!(
        cfg.token, "pre-10.0.0.1-post",
        "multiple/embedded ${{VAR}} expansion in one string"
    );
}

#[test]
fn test_env_var_expansion_undefined_becomes_empty() {
    // Guarantee the variable is unset in this process.
    std::env::remove_var("FRP_RS_TEST_ENV_UNSET");
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
token = "x${FRP_RS_TEST_ENV_UNSET}y"
"#,
    )
    .unwrap();
    assert_eq!(
        cfg.token, "xy",
        "undefined ${{VAR}} expands to the empty string (Go Viper parity)"
    );
}

#[test]
fn test_env_var_expansion_nested_positions() {
    std::env::set_var("FRP_RS_TEST_ENV_NESTED_IP", "192.168.1.5");
    std::env::set_var("FRP_RS_TEST_ENV_NESTED_NAME", "env-proxy");
    std::env::set_var("FRP_RS_TEST_ENV_NESTED_TOKEN", "secret-token");
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "${FRP_RS_TEST_ENV_NESTED_TOKEN}"

[[proxies]]
name = "${FRP_RS_TEST_ENV_NESTED_NAME}"
type = "tcp"
local_ip = "${FRP_RS_TEST_ENV_NESTED_IP}"
local_port = 8080
remote_port = 7001

[store]
path = "/tmp/${FRP_RS_TEST_ENV_NESTED_NAME}.json"
"#,
    )
    .unwrap();
    std::env::remove_var("FRP_RS_TEST_ENV_NESTED_IP");
    std::env::remove_var("FRP_RS_TEST_ENV_NESTED_NAME");
    std::env::remove_var("FRP_RS_TEST_ENV_NESTED_TOKEN");
    assert_eq!(cfg.token, "secret-token");
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.proxies[0].name, "env-proxy");
    assert_eq!(cfg.proxies[0].local_ip, "192.168.1.5");
    assert_eq!(
        cfg.store.as_ref().unwrap().path,
        "/tmp/env-proxy.json",
        "nested [store] table value expanded"
    );
}

#[test]
fn test_env_var_expansion_double_dollar_to_literal() {
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
token = "a$$b"
"#,
    )
    .unwrap();
    assert_eq!(cfg.token, "a$b", "$$ collapses to a literal $");
}

#[test]
fn test_env_var_expansion_escaped_brace_is_literal() {
    std::env::set_var("FRP_RS_TEST_ENV_ESCAPED", "SHOULD_NOT_APPEAR");
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
token = "$${FRP_RS_TEST_ENV_ESCAPED}"
"#,
    )
    .unwrap();
    std::env::remove_var("FRP_RS_TEST_ENV_ESCAPED");
    assert_eq!(
        cfg.token, "${FRP_RS_TEST_ENV_ESCAPED}",
        "$${{VAR}} stays a literal ${{VAR}} (escape hatch)"
    );
}

#[test]
fn test_env_var_expansion_ignores_bare_dollar() {
    std::env::set_var("FRP_RS_TEST_ENV_NOBRACE", "nope");
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
token = "$FRP_RS_TEST_ENV_NOBRACE"
"#,
    )
    .unwrap();
    std::env::remove_var("FRP_RS_TEST_ENV_NOBRACE");
    assert_eq!(
        cfg.token, "$FRP_RS_TEST_ENV_NOBRACE",
        "bare $VAR (no braces) is not expanded"
    );
}

#[test]
fn test_env_var_expansion_yaml_format() {
    std::env::set_var("FRP_RS_TEST_ENV_YAML_SERVER", "yaml-host");
    let cfg = load_client_config_from_yaml(
        r#"
server_addr: ${FRP_RS_TEST_ENV_YAML_SERVER}
server_port: 7000
"#,
    )
    .unwrap();
    std::env::remove_var("FRP_RS_TEST_ENV_YAML_SERVER");
    assert_eq!(
        cfg.server_addr, "yaml-host",
        "env expansion applies to all formats' toml::Value output"
    );
}

#[test]
fn test_env_var_expansion_in_include_file() {
    std::env::set_var("FRP_RS_TEST_ENV_INCLUDE_TOKEN", "inc-token");
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("frps.toml");
    std::fs::write(
        &main_path,
        r#"
bind_addr = "0.0.0.0"
bind_port = 7000
includes = ["extra.toml"]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("extra.toml"),
        r#"
token = "${FRP_RS_TEST_ENV_INCLUDE_TOKEN}"
"#,
    )
    .unwrap();
    let cfg = super::load_server_config(main_path.to_str().unwrap(), false).unwrap();
    std::env::remove_var("FRP_RS_TEST_ENV_INCLUDE_TOKEN");
    assert_eq!(
        cfg.auth.token, "inc-token",
        "include file values are env-expanded (expansion runs after includes merge)"
    );
}

#[test]
fn test_env_var_expansion_unclosed_brace_kept_verbatim() {
    // `${` with no closing `}` stays literal (no panic, no expansion).
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "abc-${UNCLOSED"
"#,
    )
    .unwrap();
    assert_eq!(
        cfg.auth.as_ref().unwrap().token,
        "abc-${UNCLOSED",
        "unclosed dollar-brace kept verbatim"
    );
}

#[test]
fn test_env_var_expansion_empty_name() {
    // `${}` (empty name) expands to the empty string.
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "a${}b"
"#,
    )
    .unwrap();
    assert_eq!(
        cfg.auth.as_ref().unwrap().token,
        "ab",
        "${{}} expands to empty string"
    );
}

// ─── Template function expansion (Go frp `{{ parseNumberRange ... }}`) ──

/// Expand `{{ parseNumberRange ... }}` in a single string through the
/// `expand_template_functions` pass (the toml::Value tree entry point).
fn expand_template_in_str(s: &str) -> String {
    let mut value = toml::Value::String(s.to_string());
    super::normalize::expand_template_functions(&mut value);
    value.as_str().unwrap().to_string()
}

#[test]
fn test_parse_number_range_basic() {
    assert_eq!(
        expand_template_in_str(r#"{{ parseNumberRange "7000-7003" }}"#),
        "7000,7001,7002,7003"
    );
    assert_eq!(
        expand_template_in_str(r#"{{ parseNumberRange "7000" }}"#),
        "7000",
        "single number"
    );
}

#[test]
fn test_parse_number_range_mixed_segments() {
    assert_eq!(
        expand_template_in_str(r#"{{ parseNumberRange "7000-7001,7005" }}"#),
        "7000,7001,7005",
        "range and single numbers mixed in one expression"
    );
    assert_eq!(
        expand_template_in_str(r#"{{ parseNumberRange "7000 , 7003-7004" }}"#),
        "7000,7003,7004",
        "whitespace around components is trimmed (Go TrimSpace semantics)"
    );
}

#[test]
fn test_parse_number_range_embedded_in_longer_string() {
    assert_eq!(
        expand_template_in_str(r#"8080,{{ parseNumberRange "9000-9001" }}"#),
        "8080,9000,9001",
        "expansion concatenated with surrounding text"
    );
    assert_eq!(
        expand_template_in_str(r#"http://127.0.0.1:{{ parseNumberRange "8000-8001" }}/path"#),
        "http://127.0.0.1:8000,8001/path",
        "expansion inside a URL-like string"
    );
}

#[test]
fn test_parse_number_range_multiple_calls_in_one_string() {
    assert_eq!(
        expand_template_in_str(
            r#"{{ parseNumberRange "7000-7001" }}|{{ parseNumberRange "9000" }}"#
        ),
        "7000,7001|9000",
        "several calls each expand in place"
    );
}

#[test]
fn test_parse_number_range_whitespace_variants() {
    assert_eq!(
        expand_template_in_str(r#"{{  parseNumberRange  "7000"  }}"#),
        "7000",
        "whitespace after {{ and before }} is allowed"
    );
    assert_eq!(
        expand_template_in_str(r#"{{parseNumberRange "7000"}}"#),
        "7000",
        "no whitespace at all is also accepted"
    );
    assert_eq!(
        expand_template_in_str("{{\n\tparseNumberRange\t\"7000\"\n}}"),
        "7000",
        "newline/tab whitespace is allowed"
    );
}

#[test]
fn test_parse_number_range_invalid_kept_verbatim() {
    let invalid = r#"{{ parseNumberRange "abc" }}"#;
    assert_eq!(
        expand_template_in_str(invalid),
        invalid,
        "non-numeric expression kept verbatim"
    );
    let reversed = r#"{{ parseNumberRange "5-2" }}"#;
    assert_eq!(
        expand_template_in_str(reversed),
        reversed,
        "N > M range kept verbatim"
    );
    let multi_dash = r#"{{ parseNumberRange "1-2-3" }}"#;
    assert_eq!(
        expand_template_in_str(multi_dash),
        multi_dash,
        "segment with more than one '-' kept verbatim"
    );
    let empty = r#"{{ parseNumberRange "" }}"#;
    assert_eq!(
        expand_template_in_str(empty),
        empty,
        "empty expression kept verbatim"
    );
}

#[test]
fn test_parse_number_range_out_of_port_range_kept_verbatim() {
    let over = r#"{{ parseNumberRange "70000" }}"#;
    assert_eq!(
        expand_template_in_str(over),
        over,
        "port above 65535 kept verbatim"
    );
    let range_over = r#"{{ parseNumberRange "60000-70000" }}"#;
    assert_eq!(
        expand_template_in_str(range_over),
        range_over,
        "range reaching above 65535 kept verbatim"
    );
    let negative = r#"{{ parseNumberRange "-1" }}"#;
    assert_eq!(
        expand_template_in_str(negative),
        negative,
        "negative port kept verbatim"
    );
}

#[test]
fn test_parse_number_range_non_call_templates_kept_verbatim() {
    // Other `{{ ... }}` text is NOT template syntax for us — only the exact
    // parseNumberRange call form is expanded (deliberate subset).
    let other = "{{ .Envs.X }}";
    assert_eq!(
        expand_template_in_str(other),
        other,
        "non-parseNumberRange template text kept verbatim"
    );
    let mixed = "a{{ parseNumberRange \"7000\" }}b{{ .Envs.X }}c";
    assert_eq!(
        expand_template_in_str(mixed),
        "a7000b{{ .Envs.X }}c",
        "only the parseNumberRange call is expanded"
    );
}

#[test]
fn test_parse_number_range_env_then_template() {
    // Env expansion runs first (env → template), so a ${VAR} inside the
    // template argument is expanded before parseNumberRange sees it.
    // RAII guard: removes the var even if the loader panics.
    struct EnvGuard(&'static str);
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }
    std::env::remove_var("FRP_RS_TEST_ENV_RANGE");
    let _guard = EnvGuard("FRP_RS_TEST_ENV_RANGE");
    std::env::set_var("FRP_RS_TEST_ENV_RANGE", "7000-7002");
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
server_port = 7000
token = '{{ parseNumberRange "${FRP_RS_TEST_ENV_RANGE}" }}'
"#,
    )
    .unwrap();
    assert_eq!(
        cfg.auth.as_ref().unwrap().token,
        "7000,7001,7002",
        "env var inside the template argument expanded first"
    );
}

#[test]
fn test_parse_number_range_full_pipeline_allow_ports() {
    // Server pipeline end-to-end: allow_ports is a comma-separated port-list
    // string, so the expansion result feeds straight into its validator.
    let cfg: ServerConfig = load_server_config_from_str(
        r#"
bind_port = 7000
allow_ports = '{{ parseNumberRange "7100-7102,7105" }}'
"#,
    )
    .unwrap();
    assert_eq!(cfg.allow_ports, "7100,7101,7102,7105");
}

#[test]
fn test_parse_number_range_array_and_table_positions() {
    let mut value: toml::Value = toml::from_str(
        r#"
port = '{{ parseNumberRange "7100-7101" }}'
list = ['{{ parseNumberRange "7200-7201" }}', 'x-{{ parseNumberRange "7300" }}-y']
[deep.nested]
range = '{{ parseNumberRange "7400-7402" }}'
"#,
    )
    .unwrap();
    super::normalize::expand_template_functions(&mut value);
    assert_eq!(
        value.get("port").and_then(toml::Value::as_str),
        Some("7100,7101"),
        "top-level string value"
    );
    let list = value.get("list").and_then(toml::Value::as_array).unwrap();
    assert_eq!(list[0].as_str(), Some("7200,7201"), "array element");
    assert_eq!(
        list[1].as_str(),
        Some("x-7300-y"),
        "embedded in array element"
    );
    assert_eq!(
        value
            .get("deep")
            .and_then(toml::Value::as_table)
            .and_then(|t| t.get("nested"))
            .and_then(toml::Value::as_table)
            .and_then(|t| t.get("range"))
            .and_then(toml::Value::as_str),
        Some("7400,7401,7402"),
        "nested table value"
    );
}

#[test]
fn test_parse_number_range_edge_inputs_kept_verbatim() {
    // Edge inputs that Go's ParseRangeNumbers rejects (or that fall outside
    // our minimal subset) must be kept verbatim, never half-expanded.
    let cases = [
        // trailing comma -> empty segment
        "{{ parseNumberRange \"7000,\" }}",
        // unclosed quote -> not a call
        "{{ parseNumberRange \"7000 }}",
        // u64-overflowing number -> no panic, kept verbatim
        "{{ parseNumberRange \"99999999999999999999\" }}",
        // escaped quote inside argument -> outside subset, kept verbatim
        "{{ parseNumberRange \"a\\\"b\" }}",
    ];
    for (i, input) in cases.iter().enumerate() {
        let mut value: toml::Value = toml::from_str(&format!("token = '{input}'")).unwrap();
        super::normalize::expand_template_functions(&mut value);
        let token = value.get("token").unwrap().as_str().unwrap();
        assert_eq!(token, *input, "case {i}: kept verbatim");
    }
}

// ─── Audit task 9 regression tests (Config/CLI Go-compat) ─────────────────

#[test]
fn test_strict_accepts_go_valid_client_keys() {
    // Go frp v0.70.1-valid client config that previously failed frpc verify
    // with "unknown field heartbeat_timeout" (audit task 9 finding 1):
    // transport.heartbeatTimeout is flattened to top-level heartbeat_timeout
    // by normalize_client_config, and the Go camelCase aliases reach the top
    // level untouched.
    let mut client_file = tempfile::NamedTempFile::new().unwrap();
    client_file
        .write_all(
            br#"serverAddr = "127.0.0.1"
serverPort = 7000
loginFailExit = true
poolCount = 4
tcpMux = true
udpPacketSize = 1500
dnsServer = "8.8.8.8"
webServer = { addr = "127.0.0.1", port = 7400 }
featureGates = { VirtualNet = true }

[transport]
heartbeatInterval = 10
heartbeatTimeout = 60
"#,
        )
        .unwrap();
    let cfg = load_client_config(client_file.path().to_str().unwrap(), true).unwrap();
    assert_eq!(cfg.heartbeat_interval, 10);
    assert_eq!(cfg.heartbeat_timeout, 60);
    assert_eq!(cfg.pool_count, 4);
    assert_eq!(cfg.udp_packet_size, 1500);
    assert_eq!(cfg.dns_server, "8.8.8.8");
    assert_eq!(cfg.web_server.port, 7400);
}

#[test]
fn test_strict_accepts_go_valid_server_aliases() {
    // Go frp v0.70.1 camelCase server aliases that normalization does not
    // rename away (audit task 9 finding 1).
    let mut server_file = tempfile::NamedTempFile::new().unwrap();
    server_file
        .write_all(
            br#"bindPort = 7000
detailedErrorsToClient = false
udpPacketSize = 2048
tcpmuxPassthrough = true
vhostHTTPTimeout = 30
maxConnections = 100
"#,
        )
        .unwrap();
    let cfg = load_server_config(server_file.path().to_str().unwrap(), true).unwrap();
    assert!(!cfg.detailed_errors_to_client);
    assert_eq!(cfg.udp_packet_size, 2048);
    assert!(cfg.tcp_mux_passthrough);
    assert_eq!(cfg.vhost_http_timeout, 30);
    assert_eq!(cfg.max_connections, Some(100));
}

#[test]
fn test_strict_rejects_nested_unknown_keys() {
    // Strict mode must recurse into sub-tables (audit task 9 finding 2):
    // unknown keys inside [log] / [auth] are caught even though the section
    // name itself is known.
    let mut log_file = tempfile::NamedTempFile::new().unwrap();
    log_file
        .write_all(
            br#"serverAddr = "127.0.0.1"
[log]
level = "info"
levell = "info"
"#,
        )
        .unwrap();
    let err = load_client_config(log_file.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(err.contains("unknown field \"log.levell\""), "got: {err}");

    let mut auth_file = tempfile::NamedTempFile::new().unwrap();
    auth_file
        .write_all(
            br#"bindPort = 7000
[auth]
token = "secret"
tokenz = "secret"
"#,
        )
        .unwrap();
    let err = load_server_config(auth_file.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(err.contains("unknown field \"auth.tokenz\""), "got: {err}");
}

#[test]
fn test_strict_accepts_go_section_keys() {
    // Go-valid keys inside known sections must pass strict mode
    // (audit task 9 findings 1+2, fix round 1: auth.additionalAuthScopes and
    // transport.v2 — both used by scripts/compat-test.sh).
    let mut server_file = tempfile::NamedTempFile::new().unwrap();
    server_file
        .write_all(
            br#"bindPort = 7000
[log]
to = "console"
maxDays = 7
disablePrintColor = true

[web_server]
addr = "0.0.0.0"
port = 7500
assetsDir = "./static"
pprofEnable = true

[transport]
tcpMux = true
heartbeatTimeout = 90
tcpKeepalive = 7200
v2 = true

[auth]
token = "secret"
additionalAuthScopes = ["HeartBeats", "NewWorkConns"]

[ssh_tunnel_gateway]
bindPort = 2200
privateKeyFile = "/etc/frp/host.key"
authorizedKeysFile = "/etc/frp/auth.keys"
allowNoneAuth = false
"#,
        )
        .unwrap();
    let cfg = load_server_config(server_file.path().to_str().unwrap(), true).unwrap();
    assert!(cfg.log.disable_print_color);
    assert_eq!(cfg.log.max_days, 7);
    assert_eq!(cfg.web_server.port, 7500);
    assert_eq!(cfg.web_server.assets_dir, "./static");
    assert!(cfg.web_server.pprof_enable);
    assert_eq!(cfg.transport.heartbeat_timeout, 90);
    assert_eq!(cfg.transport.tcp_keepalive, 7200);
    assert_eq!(cfg.ssh_tunnel_gateway.bind_port, 2200);
    assert_eq!(
        cfg.auth.additional_auth_scopes,
        vec!["HeartBeats".to_string(), "NewWorkConns".to_string()]
    );

    // Same on the client side (compat test_auth_r2g_heartbeats writes
    // additionalAuthScopes under [auth] in frpc.toml).
    let mut client_file = tempfile::NamedTempFile::new().unwrap();
    client_file
        .write_all(
            br#"server_addr = "127.0.0.1"
[auth]
method = "token"
token = "secret"
additionalAuthScopes = ["HeartBeats"]
"#,
        )
        .unwrap();
    let cfg = load_client_config(client_file.path().to_str().unwrap(), true).unwrap();
    assert_eq!(
        cfg.auth
            .as_ref()
            .map(|a| a.additional_auth_scopes.clone())
            .unwrap_or_default(),
        vec!["HeartBeats".to_string()]
    );
}

#[test]
fn test_strict_flag_false_disables_unknown_key_check() {
    // --strict-config=false must parse and disable strict mode (audit task 9
    // finding 3). The CLI flag itself is exercised in frp-core/src/cli.rs
    // tests; here the loader honors the bool.
    let mut client_file = tempfile::NamedTempFile::new().unwrap();
    client_file
        .write_all(
            br#"server_addr = "127.0.0.1"
totally_unknown_key = 1
"#,
        )
        .unwrap();
    // strict = true rejects, strict = false accepts.
    assert!(load_client_config(client_file.path().to_str().unwrap(), true).is_err());
    load_client_config(client_file.path().to_str().unwrap(), false).unwrap();
}

#[test]
fn test_allow_ports_single_form_normalized() {
    // Go allowPorts [{single=N}] must normalize to "{single=N}", not the
    // previously emitted "0-0" (audit task 9 finding 6).
    let toml_str = r#"
bind_port = 7000

[[allowPorts]]
single = 40000

[[allowPorts]]
start = 10000
end = 20000
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.allow_ports, "{single=40000},10000-20000");
    let ranges = parse_allow_ports(&cfg.allow_ports).unwrap();
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0].single, 40000, "single-port semantics preserved");
    assert!(ranges[0].contains(40000));
    assert!(!ranges[0].contains(40001));
    assert!(ranges[1].contains(15000));
}

#[test]
fn test_reversed_allow_ports_range_rejected() {
    // Go's ParseRangeNumbers rejects max < min ("range number is invalid")
    // instead of silently swapping (audit task 9 finding 7).
    let err = load_server_config_from_str("bind_port = 7000\nallow_ports = \"20000-10000\"\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("range number is invalid"), "got: {err}");
}

#[test]
fn test_proxy_validation_rejections() {
    // Go frp v0.70.1 client proxy validation (audit task 9 finding 8).
    let base = "server_addr = \"127.0.0.1\"\n[[proxies]]\nname = \"p\"\n";

    // Empty proxy name.
    let err = load_client_config_from_str(
        "server_addr = \"127.0.0.1\"\n[[proxies]]\nname = \"\"\ntype = \"tcp\"\n",
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("name should not be empty"), "got: {err}");

    // Invalid proxy protocol version.
    let err = load_client_config_from_str(&format!(
        "{base}type = \"tcp\"\nproxyProtocolVersion = \"v3\"\n"
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("not support proxy protocol version: v3"),
        "got: {err}"
    );
    // Valid versions still parse.
    for version in ["", "v1", "v2"] {
        let cfg = load_client_config_from_str(&format!(
            "{base}type = \"tcp\"\nproxyProtocolVersion = \"{version}\"\n"
        ))
        .unwrap();
        assert_eq!(cfg.proxies[0].proxy_protocol_version, version);
    }

    // Invalid health check type (Go nests health check config under
    // [proxies.healthCheck]).
    let err = load_client_config_from_str(&format!(
        "{base}type = \"tcp\"\n[proxies.healthCheck]\ntype = \"icmp\"\n"
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("not support health check type: icmp"),
        "got: {err}"
    );

    // http health check without a path.
    let err = load_client_config_from_str(&format!(
        "{base}type = \"tcp\"\n[proxies.healthCheck]\ntype = \"http\"\n"
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("health check path should not be empty"),
        "got: {err}"
    );

    // http proxy without subdomain or custom domains.
    let err = load_client_config_from_str(&format!("{base}type = \"http\"\n"))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("subdomain and custom domains should not be both empty"),
        "got: {err}"
    );

    // subdomain with '.' or '*'.
    for bad in ["a.b", "a*b"] {
        let err =
            load_client_config_from_str(&format!("{base}type = \"http\"\nsubdomain = \"{bad}\"\n"))
                .unwrap_err()
                .to_string();
        assert!(
            err.contains("'.' and '*' are not supported in subdomain"),
            "subdomain {bad:?}: got: {err}"
        );
    }

    // tcpmux also requires domains (Go validateTCPMuxProxyConfigForClient).
    let err = load_client_config_from_str(&format!(
        "{base}type = \"tcpmux\"\nmultiplexer = \"httpconnect\"\n"
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("subdomain and custom domains should not be both empty"),
        "got: {err}"
    );
}

#[test]
fn test_strict_accepts_repo_frps_toml_legacy_keys() {
    // The repo's own frps.toml example uses the frp-rs legacy keys
    // `subdomain_host` and `tls_trusted_ca_file` under [common]; strict mode
    // must accept them and serde must apply them (audit task 9 finding 1
    // family — the documented `cargo run --bin frps -- -c frps.toml`
    // workflow was broken by strict rejection).
    let toml = r#"
[common]
bind_addr = "0.0.0.0"
bind_port = 17000
subdomain_host = "example.com"
tls_enable = true
tls_trusted_ca_file = "/etc/frp/ca.pem"
auth_method = "token"
token = "secret"
log_level = "debug"
web_server_addr = "0.0.0.0"
web_server_port = 7500
tcp_mux = true
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.sub_domain_host, "example.com");
    assert_eq!(cfg.tls_ca_file, "/etc/frp/ca.pem");
}

#[test]
fn test_log_disable_print_color_parsed() {
    // log.disablePrintColor must be honored from the config file (audit task
    // 9 finding 9 — wired into resolve_ansi by the frps/frpc binaries).
    let cfg: ClientConfig =
        load_client_config_from_str("server_addr = '127.0.0.1'\n[log]\ndisablePrintColor = true\n")
            .unwrap();
    assert!(cfg.log.disable_print_color);

    let cfg: ServerConfig =
        load_server_config_from_str("bind_port = 7000\n[log]\ndisable_print_color = true\n")
            .unwrap();
    assert!(cfg.log.disable_print_color);
}

/// Go legacy INI client keys are mapped to their canonical locations
/// (Go pkg/config/legacy conversion.go).
#[test]
fn test_legacy_ini_client_gaps_mapped() {
    let cfg: ClientConfig = load_client_config_from_str(
        r#"server_addr = "127.0.0.1"
server_port = 7000
token = "t"
authenticate_heartbeats = true
authenticate_new_work_conns = true
http_proxy = "http://proxy.example:8080"
disable_log_color = true
oidc_additional_foo = "bar"
oidc_additional_aud = "baz"
"#,
    )
    .unwrap();
    let scopes = cfg
        .auth
        .as_ref()
        .map(|a| a.additional_auth_scopes.clone())
        .unwrap_or_default();
    assert!(
        scopes.contains(&"HeartBeats".to_string()),
        "scopes: {scopes:?}"
    );
    assert!(
        scopes.contains(&"NewWorkConns".to_string()),
        "scopes: {scopes:?}"
    );
    assert_eq!(cfg.proxy_url, "http://proxy.example:8080");
    assert!(cfg.log.disable_print_color);
    let oidc_params = cfg
        .auth
        .as_ref()
        .map(|a| a.additional_endpoint_params.clone())
        .unwrap_or_default();
    assert_eq!(oidc_params.get("foo"), Some(&"bar".to_string()));
    assert_eq!(oidc_params.get("aud"), Some(&"baz".to_string()));
}

/// Go legacy INI server keys (pprof_enable, dashboard_tls_mode, and the
/// dashboard_* -> web_server migration) are accepted without strict-mode
/// rejection and land in the canonical fields.
#[test]
fn test_legacy_ini_server_gaps_mapped() {
    let cfg: ServerConfig = load_server_config_from_str(
        r#"bind_port = 7000
token = "t"
dashboard_addr = "127.0.0.1"
dashboard_port = 7500
dashboard_user = "admin"
dashboard_pwd = "pw"
dashboard_tls_cert_file = "/tmp/cert.pem"
dashboard_tls_key_file = "/tmp/key.pem"
dashboard_tls_mode = true
pprof_enable = true
"#,
    )
    .unwrap();
    assert_eq!(cfg.web_server.addr, "127.0.0.1");
    assert_eq!(cfg.web_server.port, 7500);
    assert_eq!(cfg.web_server.user, "admin");
    assert_eq!(cfg.web_server.password, "pw");
    assert_eq!(cfg.web_server.tls_cert(), "/tmp/cert.pem");
    assert_eq!(cfg.web_server.tls_key(), "/tmp/key.pem");
    assert!(cfg.web_server.pprof_enable);
    // dashboard_tls_mode is consumed as a no-op (TLS driven by cert/key).
    assert!(cfg.web_server.tls_cert_file.contains("cert.pem"));
}

/// The new web_server whitelist keys are accepted in strict mode.
#[test]
fn test_strict_accepts_web_server_tls_ca_and_server_name() {
    let cfg: ServerConfig = load_server_config_from_str(
        r#"bind_port = 7000
token = "t"
[web_server]
addr = "127.0.0.1"
port = 7500
tls_cert_file = "/tmp/c.pem"
tls_key_file = "/tmp/k.pem"
trustedCaFile = "/tmp/ca.pem"
serverName = "example.com"
custom404Page = "<h1>nope</h1>"
"#,
    )
    .unwrap();
    assert_eq!(cfg.web_server.tls_ca_file, "/tmp/ca.pem");
    assert_eq!(cfg.web_server.tls_server_name, "example.com");
    assert_eq!(cfg.web_server.custom_404_page, "<h1>nope</h1>");
}

/// Load a Go legacy INI config through the real INI parser + normalize
/// pipeline (ini_to_toml rejects nothing, so [range:x] headers are legal).
fn load_client_ini(content: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut value = super::format::parse_to_toml_value(content, super::format::ConfigFormat::Ini)?;
    super::normalize::normalize_client_config(&mut value);
    let cfg: ClientConfig = serde_json::from_value(super::normalize::toml_to_json(value))
        .map_err(|e| format!("config validation error: {e}"))?;
    super::validate_client_config(&cfg)?;
    Ok(cfg)
}

/// Go legacy INI proxy sections: [web]/[ssh] become [proxies] entries,
/// [range:xxx] expands to per-port proxies, [plugin:xxx] keeps its prefix,
/// and role=visitor sections land in [visitors].
#[test]
fn test_legacy_ini_proxy_sections() {
    let cfg: ClientConfig = load_client_ini(
        r#"server_addr = "127.0.0.1"
server_port = 7000
token = "t"

[web]
type = "http"
local_port = 80
custom_domains = "web.example.com"

[ssh]
type = "tcp"
local_port = 22
remote_port = 6000

[range:test_tcp]
type = "tcp"
local_port = "6000-6002"
remote_port = "16000-16002"

[plugin:http2https]
type = "https"
remote_port = 443
custom_domains = "plugin.example.com"
plugin = "http2https"
plugin_local_addr = "127.0.0.1:80"

[xtcp_visitor]
type = "xtcp"
role = "visitor"
server_name = "xtcp_proxy"
sk = "abc123"
bind_addr = "127.0.0.1"
bind_port = 9000
"#,
    )
    .unwrap();

    let proxies = &cfg.proxies;
    let names: Vec<&str> = proxies.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"web"), "proxies: {names:?}");
    assert!(names.contains(&"ssh"), "proxies: {names:?}");

    // range:test_tcp expands to test_tcp_0/1/2 with individual ports.
    let range_names: Vec<&str> = names
        .iter()
        .filter(|n| n.starts_with("test_tcp_"))
        .copied()
        .collect();
    assert_eq!(range_names, vec!["test_tcp_0", "test_tcp_1", "test_tcp_2"]);
    let p0 = proxies.iter().find(|p| p.name == "test_tcp_0").unwrap();
    assert_eq!(p0.local_port, 6000);
    assert_eq!(p0.remote_port, 16000);

    // plugin: prefix is kept (Go parity); plugin_* keys nested into plugin.
    let ph = proxies
        .iter()
        .find(|p| p.name == "plugin:http2https")
        .unwrap();
    assert_eq!(ph.proxy_type, "https");
    let plugin = ph.plugin.as_ref().expect("plugin config");
    assert_eq!(plugin.plugin_type, "http2https");
    assert_eq!(plugin.local_addr, "127.0.0.1:80");

    // role=visitor lands in visitors with sk preserved.
    let visitors = &cfg.visitors;
    assert_eq!(visitors.len(), 1, "visitors: {visitors:?}");
    assert_eq!(visitors[0].name, "xtcp_visitor");
    assert_eq!(visitors[0].secret_key, "abc123");
    assert_eq!(visitors[0].bind_port, 9000);
}

/// Legacy INI range template with mismatched port counts is skipped (warn),
/// not fatal, and does not corrupt the remaining proxies.
#[test]
fn test_legacy_ini_range_mismatch_skipped() {
    let cfg: ClientConfig = load_client_ini(
        r#"server_addr = "127.0.0.1"
server_port = 7000

[good]
type = "tcp"
local_port = 8080
remote_port = 8081

[range:bad]
type = "tcp"
local_port = "6000-6002"
remote_port = "16000"
"#,
    )
    .unwrap();
    let names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["good"]);
}
