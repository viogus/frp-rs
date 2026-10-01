use super::*;

fn np_with_domains(domains: Vec<&str>, subdomain: Option<&str>) -> msg::NewProxy {
    let mut np = msg::NewProxy {
        proxy_name: "p1".to_string(),
        proxy_type: "http".to_string(),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: None,
        remote_port: None,
        sk: None,
        custom_domains: None,
        subdomain: None,
        locations: None,
        http_user: None,
        http_pwd: None,
        host_header_rewrite: None,
        headers: None,
        response_headers: None,
        route_by_http_user: None,
        allow_users: None,
        bandwidth_limit: None,
        bandwidth_limit_mode: None,
        annotations: None,
        metas: None,
        multiplexer: None,
        virtual_net: None,
        proxy_protocol_version: None,
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    };
    np.custom_domains = if domains.is_empty() {
        None
    } else {
        Some(domains.into_iter().map(|d| d.to_string()).collect())
    };
    np.subdomain = subdomain.map(|s| s.to_string());
    np
}

#[test]
fn custom_domain_under_subdomain_host_rejected() {
    let np = np_with_domains(vec!["api.example.com"], None);
    let err = validate_new_proxy(&np, "example.com").unwrap_err();
    assert!(
        err.contains("should not belong to subdomain host"),
        "got: {err}"
    );
}

#[test]
fn mixed_case_domain_bypass_closed() {
    // Go frp v0.71.0 fix: mixed-case "Api.Example.COM" previously
    // bypassed the subDomainHost check; now it is rejected
    // case-insensitively.
    let np = np_with_domains(vec!["Api.Example.COM"], None);
    let err = validate_new_proxy(&np, "example.com").unwrap_err();
    assert!(
        err.contains("should not belong to subdomain host"),
        "got: {err}"
    );
}

#[test]
fn unrelated_domain_allowed() {
    let np = np_with_domains(vec!["api.other.net"], None);
    assert!(validate_new_proxy(&np, "example.com").is_ok());
}

#[test]
fn exact_subdomain_host_domain_allowed() {
    // The host itself (same label count) is not a "sub" domain.
    let np = np_with_domains(vec!["example.com"], None);
    assert!(validate_new_proxy(&np, "example.com").is_ok());
}

#[test]
fn no_subdomain_host_config_means_no_check() {
    let np = np_with_domains(vec!["api.example.com"], None);
    assert!(validate_new_proxy(&np, "").is_ok());
}

#[test]
fn subdomain_field_still_validated() {
    // Go frp parity (validateDomainConfigForServer): a subdomain is
    // rejected only for '.' (label separator) or '*' (wildcard).
    let np = np_with_domains(vec![], Some("bad.subdomain"));
    let err = validate_new_proxy(&np, "example.com").unwrap_err();
    assert!(err.contains("invalid subdomain"), "got: {err}");
    // Underscores, length, leading/trailing '-' are accepted (not
    // RFC 1123 — Go parity).
    let np = np_with_domains(vec![], Some("good_sub-domain-"));
    assert!(
        validate_new_proxy(&np, "example.com").is_ok(),
        "underscore/length-tolerant subdomain must register (Go parity)"
    );
}

// Go frp v0.71.0: customDomains may carry a wildcard as the leading
// label ("*.example.com") or the bare catch-all ("*") for
// http/https/tcpmux — routing (getByRoute) replaces the leftmost label
// with "*" and walks, so those are routable. A "*" in any other
// position is never treated as a wildcard by the walk — validation
// accepts it (Go has no structure check), and it is reachable only
// by a literal host match.
#[test]
fn leading_label_wildcard_allowed() {
    let np = np_with_domains(vec!["*.example.com"], None);
    assert!(validate_new_proxy(&np, "").is_ok());
}

#[test]
fn bare_star_catch_all_allowed() {
    let np = np_with_domains(vec!["*"], None);
    assert!(validate_new_proxy(&np, "").is_ok());
}

#[test]
fn wildcard_in_nonleading_position_accepted() {
    // Go frp v0.71.0 performs NO character or structure validation on
    // customDomains — any string registers as a vhost key (routing
    // decides reachability). A "*" in a non-leading position can never
    // match a route in Go, but is accepted at register time (Go parity).
    for domain in ["a.*.com", "*.*.com", "exa*mple.com"] {
        let np = np_with_domains(vec![domain], None);
        assert!(
            validate_new_proxy(&np, "").is_ok(),
            "domain '{domain}' must be accepted at register time (Go parity)"
        );
    }
}

#[test]
fn wildcard_under_subdomain_host_rejected() {
    // Go validateDomainConfigForServer counts "*" as a label: a
    // wildcard domain under the configured host is rejected exactly
    // like any other sub-domain (contains check is ends_with, so the
    // "*.example.com" prefix needs no special handling).
    let np = np_with_domains(vec!["*.example.com"], None);
    let err = validate_new_proxy(&np, "example.com").unwrap_err();
    assert!(
        err.contains("should not belong to subdomain host"),
        "got: {err}"
    );
}

#[test]
fn wildcard_unrelated_host_allowed() {
    let np = np_with_domains(vec!["*.other.net"], None);
    assert!(validate_new_proxy(&np, "example.com").is_ok());
}
