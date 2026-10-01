//! Proxy-registration validation over `msg::NewProxy` fields, split out of
//! `proxy_ops/mod.rs`. These checks have zero `AppState` coupling, so they
//! are self-contained and self-testing.
//!
//! `mod.rs` re-imports both items privately, so the paths
//! `proxy_ops::validate_new_proxy` / `proxy_ops::duplicate_domain` and their
//! private visibility are unchanged for every existing caller. The test
//! module that covers them (`subdomain_conflict_tests`) is declared by
//! `proxy_ops/mod.rs` with a `#[path]` pointing into this directory, so its
//! `control::proxy_ops::subdomain_conflict_tests::*` test names are
//! unchanged by the move too.

use frp_core::msg;

/// First duplicated domain in a list, compared case-insensitively (Go's
/// `Routers.Add` lowercases the domain before `exist()`, so a case-only
/// variant of an earlier entry is a duplicate). Returns the lowercased
/// duplicate, or None when every entry is distinct.
pub(super) fn duplicate_domain(domains: &[String]) -> Option<String> {
    let mut seen = std::collections::HashSet::with_capacity(domains.len());
    for d in domains {
        let lowered = d.to_lowercase();
        if !seen.insert(lowered.clone()) {
            return Some(lowered);
        }
    }
    None
}

/// Pure validation of NewProxy fields. Returns Ok(()) or an error message.
/// Checks port range, proxy_name length/control chars, custom_domains length,
/// and subdomain length. Extracted from the async state machine to reduce
/// the number of `.await` points in `handle_new_proxy`.
/// `sub_domain_host` is the server's configured subDomainHost ("" = disabled);
/// it is needed for the case-insensitive custom_domains conflict check
/// (Go frp v0.71.0 `validateDomainConfigForServer`).
#[inline(never)]
pub(super) fn validate_new_proxy(np: &msg::NewProxy, sub_domain_host: &str) -> Result<(), String> {
    let raw_port = np.remote_port.unwrap_or(0);
    if raw_port < 0 || raw_port > u16::MAX as i32 {
        return Err(format!(
            "remote_port {} out of valid range (0-65535)",
            raw_port
        ));
    }
    if np.proxy_name.len() > 255 {
        return Err("proxy_name exceeds 255 characters".into());
    }
    // Reject ALL control characters (including CR/LF, which previously slipped
    // through) — proxy_name flows into vhost keys, sk_index, logs, dashboard
    // events and wire messages.
    if np.proxy_name.contains(|c: char| c.is_control()) {
        return Err("proxy_name contains invalid control characters".into());
    }
    if let Some(ref domains) = np.custom_domains {
        for domain in domains {
            // Go frp validateDomainConfigForServer performs NO character or
            // structure validation on customDomains (any string registers as
            // a vhost key; only routing decides reachability). frp-rs keeps
            // exactly the rejections that are unsafe in the vhost key space:
            // control characters (CR/LF header injection — Go's http router
            // rejects these at request time, frp-rs rejects at register time)
            // and empty entries.
            if domain.is_empty() || domain.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(format!(
                    "custom_domain '{}' is empty or contains control/whitespace characters",
                    domain
                ));
            }
        }
    }
    if let Some(ref subdomain) = np.subdomain {
        // Go frp validateDomainConfigForServer rejects a subdomain only when
        // it contains '.' (label separator — a subdomain must be a single
        // label under the vhost root) or '*' (wildcard). Underscores, length,
        // and leading/trailing '-' are accepted (Go parity, not RFC 1123).
        if subdomain.contains('.') || subdomain.contains('*') {
            return Err(format!(
                "invalid subdomain '{}' (Go frp parity: '.' and '*' are the only rejected characters)",
                subdomain
            ));
        }
    }
    // Case-insensitive custom_domains vs subDomainHost conflict check
    // (Go frp v0.71.0 fix: a mixed-case domain under the configured
    // subDomainHost previously bypassed validation). A custom domain that
    // ends with "." + subDomainHost (more labels than the host itself) is
    // rejected, mirroring Go validateDomainConfigForServer.
    if !sub_domain_host.is_empty() {
        let sub_host_lower = sub_domain_host.to_ascii_lowercase();
        let sub_host_labels = sub_host_lower.split('.').count();
        if let Some(ref domains) = np.custom_domains {
            for domain in domains {
                let canonical = domain.to_ascii_lowercase();
                let domain_labels = canonical.split('.').count();
                if domain_labels > sub_host_labels
                    && canonical.ends_with(&format!(".{sub_host_lower}"))
                {
                    return Err(format!(
                        "custom domain '{}' should not belong to subdomain host '{}'",
                        domain, sub_domain_host
                    ));
                }
            }
        }
    }
    Ok(())
}
