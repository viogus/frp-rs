//! Round-14 client-side coverage (test-completeness audit).
//!
//! `create_new_proxy_msg` is only unit-tested for the user-prefix behavior
//! of `proxy_name`; the mapping of every ProxyConfig field onto the
//! NewProxy wire message (remote_port, sk, custom_domains, group,
//! bandwidth, encryption flags) is never asserted per proxy type, and the
//! deliberate `local_str` strip for Go wire-identical JSON is unpinned.

use frp_client::proxy::create_new_proxy_msg;
use frp_core::config::ProxyConfig;
use frp_core::msg::{self, FrpMessage};

fn base_config(proxy_type: &str) -> ProxyConfig {
    ProxyConfig {
        name: "p".into(),
        proxy_type: proxy_type.into(),
        local_ip: "127.0.0.1".into(),
        local_port: 8080,
        ..Default::default()
    }
}

fn unwrap_new_proxy(msg: FrpMessage) -> msg::NewProxy {
    match msg {
        FrpMessage::NewProxy(np) => *np,
        other => panic!("expected NewProxy, got {other:?}"),
    }
}

#[test]
fn test_new_proxy_msg_tcp_maps_full_config() {
    let mut cfg = base_config("tcp");
    cfg.remote_port = 7001;
    cfg.use_encryption = true;
    cfg.use_compression = true;
    cfg.bandwidth_limit = "1MB".into();
    cfg.bandwidth_limit_mode = "server".into();
    cfg.group = "web".into();
    cfg.group_key = "gkey".into();
    cfg.annotations = [("owner".to_string(), "ops".to_string())].into();
    cfg.metas = [("env".to_string(), "prod".to_string())].into();
    cfg.proxy_protocol_version = "v2".into();

    let np = unwrap_new_proxy(create_new_proxy_msg(&cfg, "10.0.0.1:8080", ""));
    assert_eq!(np.proxy_type, "tcp");
    assert_eq!(np.remote_port, Some(7001));
    assert_eq!(np.use_encryption, Some(true));
    assert_eq!(np.use_compression, Some(true));
    assert_eq!(np.bandwidth_limit.as_deref(), Some("1MB"));
    assert_eq!(np.bandwidth_limit_mode.as_deref(), Some("server"));
    assert_eq!(np.group.as_deref(), Some("web"));
    assert_eq!(np.group_key.as_deref(), Some("gkey"));
    assert_eq!(np.proxy_protocol_version.as_deref(), Some("v2"));
    assert_eq!(
        np.annotations
            .as_ref()
            .and_then(|m| m.get("owner"))
            .map(String::as_str),
        Some("ops")
    );
    assert_eq!(
        np.metas
            .as_ref()
            .and_then(|m| m.get("env"))
            .map(String::as_str),
        Some("prod")
    );
    // local_str is deliberately stripped (proxy.rs:150-157) so the wire
    // JSON is byte-identical to Go frpc, which has no such field.
    assert!(
        np.local_str.is_none(),
        "local_str must be stripped for Go parity"
    );
    assert!(np.sk.is_none(), "tcp must not carry a secret key");
}

#[test]
fn test_new_proxy_msg_udp_and_tcpmux_carry_type_specific_fields() {
    // udp: remote_port, no domains.
    let mut udp = base_config("udp");
    udp.remote_port = 5353;
    let np = unwrap_new_proxy(create_new_proxy_msg(&udp, "127.0.0.1:53", ""));
    assert_eq!(np.proxy_type, "udp");
    assert_eq!(np.remote_port, Some(5353));
    assert!(np.custom_domains.is_none());

    // tcpmux: domains, no remote_port.
    let mut tcp_mux = base_config("tcpmux");
    tcp_mux.custom_domains = vec!["mux.example.com".into()];
    let np = unwrap_new_proxy(create_new_proxy_msg(&tcp_mux, "127.0.0.1:80", ""));
    assert_eq!(np.proxy_type, "tcpmux");
    assert_eq!(
        np.custom_domains.as_deref(),
        Some(&["mux.example.com".to_string()][..])
    );
    assert!(np.remote_port.is_none());
}

#[test]
fn test_new_proxy_msg_stcp_carries_secret_key_http_carries_domains_and_auth() {
    // stcp: sk, no remote_port.
    let mut stcp = base_config("stcp");
    stcp.sk = "s3cret".into();
    let np = unwrap_new_proxy(create_new_proxy_msg(&stcp, "127.0.0.1:22", ""));
    assert_eq!(np.proxy_type, "stcp");
    assert_eq!(np.sk.as_deref(), Some("s3cret"));
    assert!(np.remote_port.is_none());

    // http: custom_domains, subdomain, http auth, host rewrite.
    let mut http = base_config("http");
    http.custom_domains = vec!["web.example.com".into()];
    http.subdomain = "web".into();
    http.http_user = "admin".into();
    http.http_pwd = "pw".into();
    http.host_header_rewrite = "internal.example.com".into();
    let np = unwrap_new_proxy(create_new_proxy_msg(&http, "127.0.0.1:8080", ""));
    assert_eq!(np.proxy_type, "http");
    assert_eq!(
        np.custom_domains.as_deref(),
        Some(&["web.example.com".to_string()][..])
    );
    assert_eq!(np.subdomain.as_deref(), Some("web"));
    assert_eq!(np.http_user.as_deref(), Some("admin"));
    assert_eq!(np.http_pwd.as_deref(), Some("pw"));
    assert_eq!(
        np.host_header_rewrite.as_deref(),
        Some("internal.example.com")
    );
}

#[test]
fn test_new_proxy_msg_false_flags_and_zero_ports_omit_fields() {
    // Go frp uses omitempty: false flags and zero values must be absent
    // from the wire message, and the server fills its own defaults.
    let cfg = base_config("tcp");
    let np = unwrap_new_proxy(create_new_proxy_msg(&cfg, "127.0.0.1:80", ""));
    assert_eq!(np.use_encryption, None, "false flag must be omitted");
    assert_eq!(np.use_compression, None, "false flag must be omitted");
    assert_eq!(np.remote_port, None, "zero remote_port must be omitted");
    assert_eq!(np.group, None, "empty group must be omitted");
    assert_eq!(np.bandwidth_limit, None, "empty bandwidth must be omitted");
}
