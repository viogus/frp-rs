//! HTTP/HTTPS vhost route registration for a newly registered proxy.
//!
//! Split out of the `proxy_ops` parent module. Both helpers were already
//! fully extracted from the `handle_new_proxy` state machine and no test
//! region references them. The parent re-imports both privately, so
//! `proxy_ops::register_http_vhost` / `proxy_ops::register_https_vhost`
//! keep their paths and private visibility for every caller.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use frp_core::msg;

use crate::service::AppState;

use super::{err_msg, reject_new_proxy, rollback_vhost_conflict};

/// Register HTTP vhost routes for an http proxy (domains + locations,
/// subdomain expansion, catch-all fallback). On route conflict, rolls back
/// the registration, rejects the proxy, and returns `false` — the caller
/// must abort. Extracted from `handle_new_proxy`'s state machine.
#[inline(never)]
pub(super) async fn register_http_vhost(
    state: &Arc<AppState>,
    np: &msg::NewProxy,
    run_id: &str,
    port: u16,
    writer: &mut (impl AsyncWriteExt + Unpin),
    v2: bool,
) -> bool {
    let mut domains: Vec<String> = np.custom_domains.clone().unwrap_or_default();

    // Subdomain routing: {subdomain}.{sub_domain_host}
    if let Some(ref subdomain) = np.subdomain {
        if !subdomain.is_empty() {
            let sub_host = &state.sub_domain_host;
            if sub_host.is_empty() {
                // Go frp validateDomainConfigForServer rejects a subdomain
                // when SubDomainHost is unset (HTTP/HTTPS/tcpmux all route
                // through it) — mirror the tcpmux accept/reject decision
                // instead of silently dropping the route.
                rollback_vhost_conflict(state, run_id, port, false).await;
                reject_new_proxy(
                    writer,
                    &np.proxy_name,
                    "subdomain is not supported because this feature is not enabled in server"
                        .into(),
                    v2,
                )
                .await;
                state.proxy_manager.remove(&np.proxy_name).await;
                return false;
            }
            let full_domain = format!("{}.{}", subdomain, sub_host);
            info!(full_domain = %full_domain, proxy_name = %np.proxy_name, "Subdomain route: {} → {}", full_domain, np.proxy_name);
            // Go frp v0.71.0 parity: buildDomains (proxy.go:218-229) does NO
            // dedup — a subdomain expansion colliding with a custom_domains
            // entry produces a duplicate domain, and the registration loop's
            // repeated (domain, location, routeByHTTPUser) triple is then
            // rejected as a router config conflict by VhostManager::register
            // (Go: ErrRouterConfigConflict on the second Routers.Add).
            domains.push(full_domain);
        }
    }

    let locations: Vec<String> = np.locations.clone().unwrap_or_default();

    // Always register HTTP proxies with VHost manager. Round 6 (A8): an
    // HTTP proxy with BOTH empty customDomains and empty locations
    // registers NOTHING — Go's buildDomains yields an empty list and the
    // register loop (`for _, domain := range domains`) never runs, so the
    // proxy is unreachable. The old "" catch-all route (match any
    // host/path) was NOT Go parity: it hijacked every unmatched request.
    let mut locations = locations;
    let hhr = np.host_header_rewrite.as_deref().unwrap_or("");
    let http_user = np.http_user.as_deref().unwrap_or("");
    let http_pwd = np.http_pwd.as_deref().unwrap_or("");
    let rubu = np.route_by_http_user.as_deref().unwrap_or("");
    let headers: Vec<(String, String)> =
        np.headers.clone().unwrap_or_default().into_iter().collect();

    // HTTP group (Go frp v0.71.0 HTTPGroupController): members share one
    // vhost route (domain+location+routeByHTTPUser) with round-robin
    // dispatch. The first member creates the group and registers the shared
    // route; subsequent members join after group_key/params validation.
    let group_name = np.group.as_deref().unwrap_or("");
    if !group_name.is_empty() {
        // Go frp default: an empty location list means catch-all path "".
        // The group route requires exactly one (domain, location) pair.
        if locations.is_empty() {
            locations.push(String::new());
        }
        if domains.len() != 1 || locations.len() != 1 {
            rollback_vhost_conflict(state, run_id, port, false).await;
            state.proxy_manager.remove(&np.proxy_name).await;
            // Go HTTPGroup.Register runs once per (domain, location) pair
            // (proxy/http.go:76-91) against a group storing ONE pair, and
            // stops at the FIRST error — the text a Go client sees is
            // decided by the member's SECOND pair: an identical repeat
            // re-enters Register under the same proxy name and hits the
            // per-member duplicate check (`createFuncs[proxyName]`,
            // http.go:108-113) → ErrProxyRepeated "group proxy repeated";
            // a different pair fails the params comparison first
            // (http.go:100-103) → ErrGroupParamsInvalid. (customDomains
            // self-duplicates and a subdomain equal to a custom domain both
            // produce the repeat shape via buildDomains, proxy.go:218-229.)
            // frp-rs gates both shapes before any registration side effect
            // — same net rejection, with the matching wire text.
            let first_pair = (domains[0].as_str(), locations[0].as_str());
            // Pair order is domain-major, location-minor; the second pair
            // is (domains[0], locations[1]) when locations repeat.
            let second_pair = if locations.len() > 1 {
                (domains[0].as_str(), locations[1].as_str())
            } else {
                (domains[1].as_str(), locations[0].as_str())
            };
            let repeated = second_pair == first_pair;
            reject_new_proxy(
                writer,
                &np.proxy_name,
                if repeated {
                    err_msg(
                        state.detailed_errors_to_client,
                        format!(
                            "http group proxy '{}' repeats the (custom_domain, location) pair \
                             ('{}', '{}') — the identical triple re-enters HTTPGroup.Register \
                             under the same proxy name (Go: ErrProxyRepeated)",
                            np.proxy_name, first_pair.0, first_pair.1
                        ),
                        "group proxy repeated",
                    )
                } else {
                    err_msg(
                        state.detailed_errors_to_client,
                        "http group proxies must configure exactly one custom_domain and one location (Go frp HTTPGroup semantics)".into(),
                        "group params invalid",
                    )
                },
                v2,
            )
            .await;
            return false;
        }
        let domain = &domains[0];
        let location = &locations[0];
        match state
            .http_group_ctl
            .register_member(
                group_name,
                np.group_key.as_deref().unwrap_or(""),
                domain,
                location,
                rubu,
                &np.proxy_name,
            )
            .await
        {
            Ok((_group, is_first)) => {
                // Only the first member registers the shared vhost route
                // (tagged with the group name); later members just joined
                // the group's member list.
                if is_first {
                    if let Err(conflict) = state
                        .vhost_manager
                        .register(
                            &np.proxy_name,
                            &domains,
                            "http",
                            &locations,
                            run_id,
                            hhr,
                            http_user,
                            http_pwd,
                            rubu,
                            &headers,
                            group_name,
                        )
                        .await
                    {
                        state
                            .http_group_ctl
                            .unregister_member(group_name, &np.proxy_name, false)
                            .await;
                        rollback_vhost_conflict(state, run_id, port, false).await;
                        state.proxy_manager.remove(&np.proxy_name).await;
                        reject_new_proxy(
                            writer,
                            &np.proxy_name,
                            err_msg(
                                state.detailed_errors_to_client,
                                conflict.to_string(),
                                "vhost route config conflict",
                            ),
                            v2,
                        )
                        .await;
                        return false;
                    }
                }
            }
            Err(e) => {
                rollback_vhost_conflict(state, run_id, port, false).await;
                state.proxy_manager.remove(&np.proxy_name).await;
                // register_member returns the Go constants verbatim
                // ("group params invalid" / "group auth failed" /
                // "group proxy repeated" — server/group/group.go:22-26), and
                // register_member's internal ordering already chose the
                // right one for the event. Send the constant as BOTH the
                // detailed text and the non-detailed summary (mirrors the
                // https arm): masking it under one fixed summary (the old
                // "group params invalid") hid "group auth failed" /
                // "group proxy repeated" from a non-detailed frp-rs client.
                // Go in non-detailed mode would send the generic
                // "new proxy [x] error" — see err_msg's divergence note.
                reject_new_proxy(
                    writer,
                    &np.proxy_name,
                    err_msg(state.detailed_errors_to_client, e.clone(), e.as_str()),
                    v2,
                )
                .await;
                return false;
            }
        }
        info!(proxy_name = %np.proxy_name, group = %group_name, domain = %domains[0], location = %locations[0], rubu = %rubu,
            "HTTP proxy '{}' registered in group '{}' (route {} {})", np.proxy_name, group_name, domains[0], locations[0]);
        return true;
    }

    if let Err(conflict) = state
        .vhost_manager
        .register(
            &np.proxy_name,
            &domains,
            "http",
            &locations,
            run_id,
            hhr,
            http_user,
            http_pwd,
            rubu,
            &headers,
            "",
        )
        .await
    {
        // Roll back previous registrations. http proxies never consume a
        // port (remote port 0), so the rollback is a no-op — kept for
        // symmetry with the general conflict path (audit finding 8).
        rollback_vhost_conflict(state, run_id, port, false).await;
        state.proxy_manager.remove(&np.proxy_name).await;
        reject_new_proxy(
            writer,
            &np.proxy_name,
            err_msg(
                state.detailed_errors_to_client,
                conflict.to_string(),
                "vhost route config conflict",
            ),
            v2,
        )
        .await;
        return false;
    }
    info!(proxy_name = %np.proxy_name, domains = ?domains, locations = ?locations, hhr = ?hhr, "VHost routes registered for '{}': domains={:?}, locations={:?}, rewrite={:?}",
        np.proxy_name, domains, locations, hhr);
    true
}

/// Register HTTPS vhost routes for an https proxy (SNI routing, subdomain
/// expansion) and enable the SNI-sniff gate in the accept loop. On route
/// conflict, rolls back the registration, rejects the proxy, and returns
/// `false` — the caller must abort. Extracted from `handle_new_proxy`'s
/// state machine.
#[inline(never)]
pub(super) async fn register_https_vhost(
    state: &Arc<AppState>,
    np: &msg::NewProxy,
    run_id: &str,
    port: u16,
    writer: &mut (impl AsyncWriteExt + Unpin),
    v2: bool,
) -> bool {
    let mut domains: Vec<String> = np.custom_domains.clone().unwrap_or_default();

    // Subdomain routing: {subdomain}.{sub_domain_host}
    if let Some(ref subdomain) = np.subdomain {
        if !subdomain.is_empty() {
            let sub_host = &state.sub_domain_host;
            if sub_host.is_empty() {
                // Go frp validateDomainConfigForServer rejects a subdomain
                // when SubDomainHost is unset — mirror the HTTP/tcpmux
                // accept/reject decision instead of silently dropping it.
                rollback_vhost_conflict(state, run_id, port, false).await;
                reject_new_proxy(
                    writer,
                    &np.proxy_name,
                    "subdomain is not supported because this feature is not enabled in server"
                        .into(),
                    v2,
                )
                .await;
                state.proxy_manager.remove(&np.proxy_name).await;
                return false;
            }
            let full_domain = format!("{}.{}", subdomain, sub_host);
            // No dedup (Go buildDomains parity): a subdomain expansion
            // colliding with a custom_domains entry is a duplicate domain,
            // and VhostManager::register rejects the repeated
            // (domain, "", routeByHTTPUser) SNI triple as a config conflict.
            domains.push(full_domain);
        }
    }

    if domains.is_empty() {
        warn!(proxy_name = %np.proxy_name, "HTTPS proxy '{}' has no custom_domains — SNI routing won't work", np.proxy_name);
    }

    let hhr = np.host_header_rewrite.as_deref().unwrap_or("");
    let http_user = np.http_user.as_deref().unwrap_or("");
    let http_pwd = np.http_pwd.as_deref().unwrap_or("");
    let rubu = np.route_by_http_user.as_deref().unwrap_or("");
    let headers: Vec<(String, String)> =
        np.headers.clone().unwrap_or_default().into_iter().collect();

    // HTTPS group (Go frp v0.71.0 HTTPSGroup.Listen, server/group/https.go,
    // SNI routing — audit round-8 F5).
    let group_name = np.group.as_deref().unwrap_or("");
    if !group_name.is_empty() {
        // Go runs one listen per custom_domain entry: repeated IDENTICAL
        // domains register the same group member once, while a second
        // DIFFERENT domain is ErrGroupParamsInvalid. Collapse duplicates
        // (order-preserving) so the count check separates the two cases and
        // the first-member route registration is not handed duplicates.
        let mut group_domains: Vec<String> = domains.clone();
        let mut seen = std::collections::HashSet::new();
        group_domains.retain(|d| seen.insert(d.clone()));
        if group_domains.len() != 1 {
            rollback_vhost_conflict(state, run_id, port, false).await;
            state.proxy_manager.remove(&np.proxy_name).await;
            reject_new_proxy(
                writer,
                &np.proxy_name,
                err_msg(
                    state.detailed_errors_to_client,
                    "https group proxies must configure exactly one distinct custom_domain (Go frp HTTPSGroup semantics)".into(),
                    "group params invalid",
                ),
                v2,
            )
            .await;
            return false;
        }
        let domain = &group_domains[0];
        // HTTPS group membership compares ONLY group name + domain — location
        // and route_by_http_user never participate (Go listenForDomain builds
        // an empty RouteConfig; HTTPSProxyConfig cannot even express rubu).
        // The https-kind register rejects cross-kind joins and returns the Go
        // constants verbatim ("group params invalid" / "group auth failed").
        match state
            .http_group_ctl
            .register_https_member(
                group_name,
                np.group_key.as_deref().unwrap_or(""),
                domain,
                &np.proxy_name,
            )
            .await
        {
            Ok((_group, is_first)) => {
                if is_first {
                    if let Err(conflict) = state
                        .vhost_manager
                        .register(
                            &np.proxy_name,
                            &group_domains,
                            "https",
                            &[], // no locations for HTTPS SNI routing
                            run_id,
                            hhr,
                            http_user,
                            http_pwd,
                            // Go parity: HTTPSProxyConfig is ProxyBaseConfig +
                            // DomainConfig ONLY (pkg/config/v1/proxy.go) — Go's
                            // HTTPSProxy never sets RouteByHTTPUser (https.go
                            // listenForDomain builds an empty RouteConfig), so
                            // the SNI route is always keyed by "" and the SNI
                            // lookup (http_user "") can find it. Registering
                            // under rubu instead would make the proxy silently
                            // unreachable and let two HTTPS proxies on the same
                            // domain with different rubu pass the conflict
                            // check where Go rejects the second.
                            "",
                            &headers,
                            group_name,
                        )
                        .await
                    {
                        state
                            .http_group_ctl
                            .unregister_member(group_name, &np.proxy_name, true)
                            .await;
                        rollback_vhost_conflict(state, run_id, port, false).await;
                        state.proxy_manager.remove(&np.proxy_name).await;
                        reject_new_proxy(
                            writer,
                            &np.proxy_name,
                            err_msg(
                                state.detailed_errors_to_client,
                                conflict.to_string(),
                                "vhost route config conflict",
                            ),
                            v2,
                        )
                        .await;
                        return false;
                    }
                }
            }
            Err(e) => {
                rollback_vhost_conflict(state, run_id, port, false).await;
                state.proxy_manager.remove(&np.proxy_name).await;
                // register_https_member returns the Go constants verbatim
                // ("group params invalid" / "group auth failed",
                // server/group/group.go:22-26). The kind-keyed registry
                // means a cross-kind join is structurally impossible — no
                // non-Go text can reach this arm anymore.
                reject_new_proxy(
                    writer,
                    &np.proxy_name,
                    err_msg(state.detailed_errors_to_client, e.clone(), e.as_str()),
                    v2,
                )
                .await;
                return false;
            }
        }
        info!(proxy_name = %np.proxy_name, group = %group_name, domain = %domains[0], rubu = %rubu,
            "HTTPS proxy '{}' registered in group '{}' (SNI {})", np.proxy_name, group_name, domains[0]);
        return true;
    }

    if let Err(conflict) = state
        .vhost_manager
        .register(
            &np.proxy_name,
            &domains,
            "https",
            &[], // no locations for HTTPS SNI routing
            run_id,
            hhr,
            http_user,
            http_pwd,
            // Go parity: HTTPSProxyConfig is ProxyBaseConfig + DomainConfig
            // ONLY (pkg/config/v1/proxy.go) — Go's HTTPSProxy never sets
            // RouteByHTTPUser (https.go listenForDomain builds an empty
            // RouteConfig), so the SNI route is always keyed by "" and the
            // SNI lookup (http_user "") can find it. Registering under rubu
            // instead would make the proxy silently unreachable and let two
            // HTTPS proxies on the same domain with different rubu pass the
            // conflict check where Go rejects the second.
            "",
            &headers,
            "",
        )
        .await
    {
        // Roll back previous registrations. https proxies never consume a
        // port (remote port 0), so the rollback is a no-op — kept for
        // symmetry with the general conflict path (audit finding 8).
        rollback_vhost_conflict(state, run_id, port, false).await;
        state.proxy_manager.remove(&np.proxy_name).await;
        reject_new_proxy(
            writer,
            &np.proxy_name,
            err_msg(
                state.detailed_errors_to_client,
                conflict.to_string(),
                "vhost route config conflict",
            ),
            v2,
        )
        .await;
        return false;
    }
    // Account this non-group HTTPS proxy's SNI routes (group proxies return
    // above without incrementing — audit round 6d asymmetry, documented on
    // the field). Decremented on unregister/close (unregister_control,
    // handle_close_proxy, dashboard proxy delete).
    state.https_proxy_count.fetch_add(1, Ordering::Relaxed);
    info!(
        proxy_name = %np.proxy_name, domains = ?domains, "VHost SNI routes registered for HTTPS proxy '{}': domains={:?}",
        np.proxy_name, domains
    );
    true
}
