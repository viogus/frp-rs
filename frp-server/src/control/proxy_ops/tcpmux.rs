//! TCPMux route registration for a newly registered proxy.
//!
//! Extracted from the `handle_new_proxy` state machine (the inline tcpmux
//! arm became `register_tcpmux_proxy`, mirroring `register_http_vhost` /
//! `register_https_vhost`). The parent re-imports it privately, so
//! `proxy_ops::tcpmux` stays an internal path.

use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::info;

use frp_core::msg;

use crate::service::AppState;

use super::validate::duplicate_domain;
use super::{err_msg, reject_new_proxy, rollback_vhost_conflict};

/// Register TCPMux routes for a tcpmux proxy (domains, subdomain expansion,
/// duplicate-domain gate, and the load-balancing group path). On route
/// conflict, rolls back the registration, rejects the proxy, and returns
/// `false` — the caller must abort. Extracted from `handle_new_proxy`'s
/// state machine.
#[inline(never)]
pub(super) async fn register_tcpmux_proxy(
    state: &Arc<AppState>,
    np: &msg::NewProxy,
    run_id: &str,
    port: u16,
    writer: &mut (impl AsyncWriteExt + Unpin),
    v2: bool,
) -> bool {
    // Go frp v0.71.0 parity (server/proxy/tcpmux.go `Run()`):
    // only the httpconnect multiplexer is valid — anything else
    // rejects with `unknown multiplexer [%s]`. frp-rs accepts ""
    // as a lenient default (documented divergence: Go rejects
    // "", but existing frp-rs configs omit the field and the
    // client only ever sends httpconnect).
    let multiplexer = np.multiplexer.as_deref().unwrap_or("");
    if !multiplexer.is_empty() && multiplexer != "httpconnect" {
        rollback_vhost_conflict(state, run_id, port, false).await;
        state.proxy_manager.remove(&np.proxy_name).await;
        reject_new_proxy(
            writer,
            &np.proxy_name,
            format!("unknown multiplexer [{}]", multiplexer),
            v2,
        )
        .await;
        return false;
    }
    let mut domains: Vec<String> = np.custom_domains.clone().unwrap_or_default();

    // Subdomain routing: {subdomain}.{sub_domain_host} — Go
    // frp v0.71.0 TCPMuxProxy::httpConnectRun routes
    // buildDomains(CustomDomains, SubDomain), so a
    // subdomain-only tcpmux proxy is valid (frpc sends
    // subdomain for tcpmux). Go's
    // validateDomainConfigForServer REJECTS a subdomain when
    // SubDomainHost is unset — the HTTP/HTTPS paths mirror
    // this accept/reject decision (C1).
    if let Some(ref subdomain) = np.subdomain {
        if !subdomain.is_empty() {
            let sub_host = &state.sub_domain_host;
            if sub_host.is_empty() {
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
            // No dedup (Go buildDomains parity): a subdomain
            // expansion colliding with a custom_domains entry is
            // a duplicate domain — rejected below by the
            // duplicate-domain gate (Go: the second Muxer.Listen
            // → Routers.Add hits exist() and rejects).
            domains.push(full_domain);
        }
    }

    if domains.is_empty() {
        // TCPMux requires at least one domain for routing
        rollback_vhost_conflict(state, run_id, port, false).await;
        reject_new_proxy(
            writer,
            &np.proxy_name,
            "tcpmux proxy requires custom_domains".into(),
            v2,
        )
        .await;
        state.proxy_manager.remove(&np.proxy_name).await;
        return false;
    }
    // Go buildDomains parity (server/proxy/proxy.go:218-229):
    // empty custom_domains entries are SKIPPED (`if d != ""`),
    // so custom_domains=["",""] yields zero domains and the
    // proxy is ACCEPTED (Muxer.Listen never runs, listens
    // nothing). Filter before the duplicate gate so ["",""]
    // can't trip it; the register below with an empty list is a
    // no-op. The len(customDomains)==0 gate above stays on the
    // raw list (Go checks it before buildDomains).
    let domains: Vec<String> = domains.into_iter().filter(|d| !d.is_empty()).collect();
    // Go frp v0.71.0 parity (tcpmux.go httpConnectRun →
    // httpConnectListen → Muxer.Listen → Routers.Add): buildDomains
    // does no dedup, so a duplicate domain within one proxy's own
    // list (duplicate custom_domains entry, subdomain expansion
    // colliding with a custom_domains entry, or a case-only
    // variant — Add lowercases before exist()) repeats the
    // (domain, "", routeByHTTPUser) triple and the second Add
    // REJECTS the whole registration. The tcpmux manager's
    // per-(domain, routeByHTTPUser) HashMap insert is idempotent
    // for same-proxy re-registration, so the reject happens here.
    if let Some(dup) = duplicate_domain(&domains) {
        rollback_vhost_conflict(state, run_id, port, false).await;
        state.proxy_manager.remove(&np.proxy_name).await;
        reject_new_proxy(
            writer,
            &np.proxy_name,
            err_msg(
                state.detailed_errors_to_client,
                format!(
                    "tcpmux proxy custom_domains contains duplicate domain '{}'",
                    dup
                ),
                "tcpmux route config conflict",
            ),
            v2,
        )
        .await;
        return false;
    }
    let http_user = np.http_user.as_deref().unwrap_or("");
    let http_pwd = np.http_pwd.as_deref().unwrap_or("");
    let headers: Vec<(String, String)> =
        np.headers.clone().unwrap_or_default().into_iter().collect();

    // TCPMux load-balancing group (Go frp v0.71.0
    // group.TCPMuxGroupController + server/proxy/tcpmux.go
    // httpConnectListen): when LoadBalancer.Group is set the
    // Listen goes through the group controller — the FIRST
    // member creates the group and registers the shared muxer
    // route; later members are validated against it (params
    // equal → "group params invalid" ErrGroupParamsInvalid,
    // group_key equal → "group auth failed" ErrGroupAuthFailed,
    // both verbatim, Go check order) and join the fan-out.
    // M2 audit fix: second members were previously rejected as
    // plain route conflicts, silently disabling the documented
    // multi-client load-balanced tcpmux feature.
    //
    // Go's TCPMuxGroup stores ONE (domain, rubu, user, pwd) per
    // group name — a same-group proxy whose second domain
    // differs from the first member's is rejected with
    // ErrGroupParamsInvalid. Mirrored up front like the HTTP
    // group path ("http group proxies must configure exactly
    // one custom_domain and one location"), instead of failing
    // mid-registration.
    let group_name = np.group.as_deref().unwrap_or("");
    if !group_name.is_empty() {
        if domains.len() != 1 {
            rollback_vhost_conflict(state, run_id, port, false).await;
            state.proxy_manager.remove(&np.proxy_name).await;
            reject_new_proxy(
                writer,
                &np.proxy_name,
                err_msg(
                    state.detailed_errors_to_client,
                    "tcpmux group proxies must configure exactly one custom_domain (Go frp TCPMuxGroup semantics)".into(),
                    "tcpmux group params invalid",
                ),
                v2,
            )
            .await;
            return false;
        }
        let domain = &domains[0];
        match state
            .tcpmux_group_ctl
            .register_member(
                group_name,
                np.group_key.as_deref().unwrap_or(""),
                domain,
                np.route_by_http_user.as_deref().unwrap_or(""),
                http_user,
                http_pwd,
                &np.proxy_name,
            )
            .await
        {
            Ok((_group, is_first)) => {
                // Only the first member registers the shared
                // tcpmux route (tagged with the group name);
                // later members just joined the member list.
                if is_first {
                    if let Err(conflict) = state
                        .tcpmux_manager
                        .register(
                            &np.proxy_name,
                            &domains,
                            run_id,
                            http_user,
                            http_pwd,
                            // Round 6 (A2): route_by_http_user is
                            // the second tcpmux routing dimension
                            // (Go RouteConfig) — CONNECT lookups
                            // match the request user's bucket
                            // first.
                            np.route_by_http_user.as_deref().unwrap_or(""),
                            &headers,
                            group_name,
                        )
                        .await
                    {
                        state
                            .tcpmux_group_ctl
                            .unregister_member(group_name, &np.proxy_name)
                            .await;
                        rollback_vhost_conflict(state, run_id, port, false).await;
                        state.proxy_manager.remove(&np.proxy_name).await;
                        reject_new_proxy(
                            writer,
                            &np.proxy_name,
                            err_msg(
                                state.detailed_errors_to_client,
                                conflict,
                                "tcpmux route config conflict",
                            ),
                            v2,
                        )
                        .await;
                        return false;
                    }
                }
            }
            Err(e) => {
                // e is the verbatim Go rejection ("group params
                // invalid" / "group auth failed").
                rollback_vhost_conflict(state, run_id, port, false).await;
                state.proxy_manager.remove(&np.proxy_name).await;
                reject_new_proxy(
                    writer,
                    &np.proxy_name,
                    err_msg(
                        state.detailed_errors_to_client,
                        e,
                        "tcpmux group registration failed",
                    ),
                    v2,
                )
                .await;
                return false;
            }
        }
        info!(
            proxy_name = %np.proxy_name, group = %group_name, domain = %domain,
            rubu = %np.route_by_http_user.as_deref().unwrap_or(""),
            "TCPMux proxy '{}' registered in group '{}' (route {})",
            np.proxy_name, group_name, domain
        );
    } else if let Err(conflict) = state
        .tcpmux_manager
        .register(
            &np.proxy_name,
            &domains,
            run_id,
            http_user,
            http_pwd,
            // Round 6 (A2): route_by_http_user is the second
            // tcpmux routing dimension (Go RouteConfig) — CONNECT
            // lookups match the request user's bucket first.
            np.route_by_http_user.as_deref().unwrap_or(""),
            &headers,
            "",
        )
        .await
    {
        // Roll back previous registrations (mirror
        // register_http_vhost). tcpmux proxies never consume a
        // port, so the rollback is a no-op (audit finding 8).
        rollback_vhost_conflict(state, run_id, port, false).await;
        state.proxy_manager.remove(&np.proxy_name).await;
        reject_new_proxy(
            writer,
            &np.proxy_name,
            err_msg(
                state.detailed_errors_to_client,
                conflict,
                "tcpmux route config conflict",
            ),
            v2,
        )
        .await;
        return false;
    }
    if group_name.is_empty() {
        info!(
            proxy_name = %np.proxy_name, domains = ?domains, "TCPMux routes registered for '{}': domains={:?}",
            np.proxy_name, domains
        );
    }
    true
}
