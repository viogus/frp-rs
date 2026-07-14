//! Dashboard API v2 — paginated, filterable, searchable endpoints.
//! Go frp v0.70.0 compat: /api/v2/* routes.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::collections::HashMap;
use axum::{Router, Json, extract::{State, Path, Query}, routing::{get, post}};
use axum::http::StatusCode;
use serde::Serialize;
use crate::service::AppState;

// ── Generic page response ──────────────────────────────────────────

#[derive(Serialize)]
struct V2PageResp<T: Serialize> {
    total: usize,
    page: u32,
    #[serde(rename = "pageSize")]
    page_size: u32,
    items: Vec<T>,
}

// ── Error ───────────────────────────────────────────────────────────

#[derive(Serialize)]
struct V2Error {
    error: String,
}

fn v2_err(s: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<V2Error>) {
    (s, Json(V2Error { error: msg.into() }))
}

// ── System info ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct V2SystemInfoConfig {
    #[serde(rename = "bindPort")]
    bind_port: u16,
    #[serde(rename = "vhostHTTPPort")]
    vhost_http_port: u16,
    #[serde(rename = "vhostHTTPSPort")]
    vhost_https_port: u16,
    #[serde(rename = "tcpmuxHTTPConnectPort")]
    tcpmux_httpconnect_port: u16,
    #[cfg(feature = "kcp")]
    #[serde(rename = "kcpBindPort")]
    kcp_bind_port: u16,
    #[cfg(feature = "quic")]
    #[serde(rename = "quicBindPort")]
    quic_bind_port: u16,
    #[serde(rename = "subdomainHost")]
    subdomain_host: String,
    #[serde(rename = "maxPoolCount")]
    max_pool_count: i64,
    #[serde(rename = "maxPortsPerClient")]
    max_ports_per_client: i64,
    #[serde(rename = "heartbeatTimeout")]
    heartbeat_timeout: i64,
    #[serde(rename = "allowPortsStr")]
    allow_ports_str: String,
    #[serde(rename = "tlsForce")]
    tls_force: bool,
}

#[derive(Serialize)]
struct V2SystemInfoStatus {
    #[serde(rename = "totalTrafficIn")]
    total_traffic_in: i64,
    #[serde(rename = "totalTrafficOut")]
    total_traffic_out: i64,
    #[serde(rename = "curConns")]
    cur_conns: i64,
    #[serde(rename = "clientCounts")]
    client_counts: i64,
    #[serde(rename = "proxyTypeCount")]
    proxy_type_counts: HashMap<String, i64>,
}

#[derive(Serialize)]
struct V2SystemInfoResp {
    version: String,
    config: V2SystemInfoConfig,
    status: V2SystemInfoStatus,
}

#[derive(Serialize)]
struct V2SystemPruneResp {
    #[serde(rename = "type")]
    prune_type: String,
    cleared: usize,
    total: usize,
}

// ── Users ────────────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
struct V2UserResp {
    user: String,
    #[serde(rename = "clientCount")]
    client_count: usize,
    #[serde(rename = "proxyCount")]
    proxy_count: usize,
}

// ── Clients ──────────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
struct V2ClientEntry {
    #[serde(rename = "runID")]
    run_id: String,
    #[serde(rename = "clientAddr")]
    client_addr: Option<String>,
    online: bool,
    #[serde(rename = "loginTimeSecs")]
    login_time_secs: u64,
    #[serde(rename = "proxyCount")]
    proxy_count: usize,
    proxies: Vec<String>,
    #[serde(rename = "poolSize")]
    pool_size: i64,
    #[serde(rename = "pendingRequests")]
    pending_requests: i64,
}

#[derive(Serialize)]
struct V2ClientDetailResp {
    #[serde(flatten)]
    info: V2ClientEntry,
    status: V2ClientStatus,
}

#[derive(Serialize)]
struct V2ClientStatus {
    phase: String,
    #[serde(rename = "curConns")]
    cur_conns: i64,
    #[serde(rename = "proxyCount")]
    proxy_count: i64,
}

// ── Proxies ──────────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
struct V2ProxyResp {
    name: String,
    user: String,
    #[serde(rename = "clientID")]
    client_id: String,
    spec: V2ProxySpec,
    status: V2ProxyStatus,
}

#[derive(Serialize, Clone, Default)]
struct V2ProxySpec {
    #[serde(rename = "type")]
    proxy_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp: Option<V2TcpUdpSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp: Option<V2TcpUdpSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http: Option<V2HttpSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    https: Option<V2HttpsSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcpmux: Option<V2TcpMuxSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stcp: Option<V2BaseOnlySpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sudp: Option<V2BaseOnlySpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    xtcp: Option<V2BaseOnlySpec>,
}

#[derive(Serialize, Clone)]
struct V2ProxyBaseSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<V2ProxyTransport>,
    #[serde(rename = "loadBalancer", skip_serializing_if = "Option::is_none")]
    load_balancer: Option<V2LoadBalancer>,
}

#[derive(Serialize, Clone)]
struct V2ProxyTransport {
    #[serde(rename = "useEncryption")]
    use_encryption: bool,
    #[serde(rename = "useCompression")]
    use_compression: bool,
    #[serde(rename = "bandwidthLimit")]
    bandwidth_limit: String,
    #[serde(rename = "bandwidthLimitMode")]
    bandwidth_limit_mode: String,
}

#[derive(Serialize, Clone)]
struct V2LoadBalancer {
    group: String,
}

#[derive(Serialize, Clone)]
struct V2TcpUdpSpec {
    #[serde(flatten)]
    base: V2ProxyBaseSpec,
    #[serde(rename = "remotePort", skip_serializing_if = "Option::is_none")]
    remote_port: Option<u16>,
}

#[derive(Serialize, Clone)]
struct V2HttpSpec {
    #[serde(flatten)]
    base: V2ProxyBaseSpec,
    #[serde(rename = "customDomains", skip_serializing_if = "Vec::is_empty")]
    custom_domains: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    subdomain: String,
    #[serde(rename = "hostHeaderRewrite", skip_serializing_if = "String::is_empty")]
    host_header_rewrite: String,
}

#[derive(Serialize, Clone)]
struct V2HttpsSpec {
    #[serde(flatten)]
    base: V2ProxyBaseSpec,
    #[serde(rename = "customDomains", skip_serializing_if = "Vec::is_empty")]
    custom_domains: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    subdomain: String,
}

#[derive(Serialize, Clone)]
struct V2TcpMuxSpec {
    #[serde(flatten)]
    base: V2ProxyBaseSpec,
    #[serde(rename = "customDomains", skip_serializing_if = "Vec::is_empty")]
    custom_domains: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    subdomain: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    multiplexer: String,
}

#[derive(Serialize, Clone)]
struct V2BaseOnlySpec {
    #[serde(flatten)]
    base: V2ProxyBaseSpec,
}

#[derive(Serialize, Clone)]
struct V2ProxyStatus {
    phase: String,
    #[serde(rename = "todayTrafficIn")]
    today_traffic_in: u64,
    #[serde(rename = "todayTrafficOut")]
    today_traffic_out: u64,
    #[serde(rename = "curConns")]
    cur_conns: i64,
    #[serde(rename = "lastStartAt", skip_serializing_if = "is_zero")]
    last_start_at: i64,
    #[serde(rename = "lastCloseAt", skip_serializing_if = "is_zero")]
    last_close_at: i64,
}

fn is_zero(v: &i64) -> bool { *v == 0 }

// ── Traffic ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct V2ProxyTrafficResp {
    name: String,
    unit: String,
    granularity: String,
    history: Vec<V2TrafficPoint>,
}

#[derive(Serialize)]
struct V2TrafficPoint {
    date: String,
    #[serde(rename = "trafficIn")]
    traffic_in: i64,
    #[serde(rename = "trafficOut")]
    traffic_out: i64,
}

// ── Helpers ──────────────────────────────────────────────────────────

const DEFAULT_PAGE: u32 = 1;
const DEFAULT_PAGE_SIZE: u32 = 50;
const MAX_PAGE_SIZE: u32 = 200;

const VALID_TYPES: &[&str] = &["tcp", "udp", "http", "https", "tcpmux", "stcp", "xtcp", "sudp"];

fn parse_page(p: Option<u32>, ps: Option<u32>) -> Result<(u32, u32), (StatusCode, Json<V2Error>)> {
    let page = p.unwrap_or(DEFAULT_PAGE).max(1);
    let size = ps.unwrap_or(DEFAULT_PAGE_SIZE).max(1);
    if size > MAX_PAGE_SIZE {
        return Err(v2_err(StatusCode::BAD_REQUEST, format!("pageSize must be <= {MAX_PAGE_SIZE}")));
    }
    Ok((page, size))
}

fn paginate<T: Serialize>(mut items: Vec<T>, page: u32, page_size: u32) -> V2PageResp<T> {
    let total = items.len();
    let start = ((page as usize).saturating_sub(1)).saturating_mul(page_size as usize);
    let items = if start >= total {
        Vec::new()
    } else {
        let end = (start + page_size as usize).min(total);
        items.drain(start..end).collect()
    };
    V2PageResp { total, page, page_size, items }
}

fn match_status(online: bool, filter: &str) -> bool {
    match filter {
        "" | "all" => true,
        "online" => online,
        "offline" => !online,
        _ => true,
    }
}

fn match_search(q: &str, values: &[&str]) -> bool {
    if q.is_empty() { return true; }
    let q = q.to_lowercase();
    values.iter().any(|v| v.to_lowercase().contains(&q))
}

fn validate_type(t: &str) -> Result<(), (StatusCode, Json<V2Error>)> {
    if t.is_empty() || VALID_TYPES.contains(&t) {
        Ok(())
    } else {
        Err(v2_err(StatusCode::BAD_REQUEST, "type must be one of tcp, udp, http, https, tcpmux, stcp, xtcp, sudp"))
    }
}

fn validate_status(s: &str) -> Result<(), (StatusCode, Json<V2Error>)> {
    match s {
        "" | "all" | "online" | "offline" => Ok(()),
        _ => Err(v2_err(StatusCode::BAD_REQUEST, "status must be all, online, or offline")),
    }
}

/// Percent-decode a URL-encoded path segment. Only needed for proxy/client
/// names that might contain special characters.
fn percent_decode_path(s: &str) -> Result<String, (StatusCode, Json<V2Error>)> {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_nibble(bytes[i + 1]);
                let lo = hex_nibble(bytes[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4 | l) as char);
                    i += 3;
                } else {
                    return Err(v2_err(StatusCode::BAD_REQUEST, "invalid percent-encoding"));
                }
            }
            b'+' => { out.push(' '); i += 1; }
            b => { out.push(b as char); i += 1; }
        }
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Format a Unix timestamp (seconds) as YYYY-MM-DD.
fn format_date_ymd(ts_secs: i64) -> String {
    if ts_secs <= 0 {
        return String::new();
    }
    // days since Unix epoch
    let days = ts_secs / 86400;
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + (era * 400);
    let doy = doe as i64 - (365 * yoe as i64 + yoe as i64 / 4 - yoe as i64 / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn proxy_base_spec(info: &crate::proxy::ProxyInfo) -> V2ProxyBaseSpec {
    V2ProxyBaseSpec {
        transport: Some(V2ProxyTransport {
            use_encryption: info.use_encryption,
            use_compression: info.use_compression,
            bandwidth_limit: String::new(),
            bandwidth_limit_mode: String::new(),
        }),
        load_balancer: info.group.as_ref().map(|g| V2LoadBalancer { group: g.clone() }),
    }
}

fn proxy_spec(info: &crate::proxy::ProxyInfo) -> V2ProxySpec {
    // Match on proxy type once; move base into the matching variant.
    // Avoids 7 unnecessary clone()s of the V2ProxyBaseSpec.
    macro_rules! spec {
        ($variant:ident, $ctor:expr) => {{
            let base = proxy_base_spec(info);
            let mut s = V2ProxySpec::default();
            s.$variant = Some($ctor(base));
            s
        }};
    }
    match info.proxy_type.as_str() {
        "tcp" => spec!(tcp, |base| V2TcpUdpSpec { base, remote_port: info.remote_port }),
        "udp" => spec!(udp, |base| V2TcpUdpSpec { base, remote_port: info.remote_port }),
        "http" => spec!(http, |base| V2HttpSpec {
            base,
            custom_domains: info.custom_domains.clone(),
            subdomain: String::new(),
            host_header_rewrite: String::new(),
        }),
        "https" => spec!(https, |base| V2HttpsSpec {
            base,
            custom_domains: info.custom_domains.clone(),
            subdomain: String::new(),
        }),
        "tcpmux" => spec!(tcpmux, |base| V2TcpMuxSpec {
            base,
            custom_domains: info.custom_domains.clone(),
            subdomain: String::new(),
            multiplexer: info.multiplexer.clone(),
        }),
        "stcp" => spec!(stcp, |base| V2BaseOnlySpec { base }),
        "sudp" => spec!(sudp, |base| V2BaseOnlySpec { base }),
        "xtcp" => spec!(xtcp, |base| V2BaseOnlySpec { base }),
        _ => V2ProxySpec { proxy_type: info.proxy_type.clone(), ..Default::default() },
    }
}

// ── Query params ─────────────────────────────────────────────────────

use serde::Deserialize;

#[derive(Deserialize, Default)]
struct UserQuery { page: Option<u32>, #[serde(rename = "pageSize")] page_size: Option<u32>, q: Option<String> }

#[derive(Deserialize, Default)]
struct ClientQuery {
    page: Option<u32>, #[serde(rename = "pageSize")] page_size: Option<u32>,
    status: Option<String>, user: Option<String>,
    #[serde(rename = "clientID")] client_id: Option<String>,
    #[serde(rename = "runID")] run_id: Option<String>,
    q: Option<String>,
}

#[derive(Deserialize, Default)]
struct ProxyQuery {
    page: Option<u32>, #[serde(rename = "pageSize")] page_size: Option<u32>,
    status: Option<String>, #[serde(rename = "type")] proxy_type: Option<String>,
    user: Option<String>, #[serde(rename = "clientID")] client_id: Option<String>,
    q: Option<String>,
}

#[derive(Deserialize)]
struct PruneQuery { #[serde(rename = "type")] prune_type: String }

// ── Handlers ─────────────────────────────────────────────────────────

async fn handle_v2_system_info(State(state): State<Arc<AppState>>) -> Json<V2SystemInfoResp> {
    let snap = &state.server_config_snapshot;
    let ctl_map = state.run_id_to_ctl_tx.read().await;
    let client_count = ctl_map.len() as i64;
    drop(ctl_map);

    let proxies = state.proxy_manager.list().await;
    let mut proxy_type_counts: HashMap<String, i64> = HashMap::new();
    for p in &proxies {
        *proxy_type_counts.entry(p.proxy_type.clone()).or_insert(0) += 1;
    }

    // Aggregate traffic/conns from proxy_metrics
    let mut total_in: i64 = 0;
    let mut total_out: i64 = 0;
    let mut cur_conns: i64 = 0;
    for p in &proxies {
        if let Some(m) = state.proxy_metrics.get(&p.name).await {
            let snap = m.snapshot();
            total_in += snap.bytes_in as i64;
            total_out += snap.bytes_out as i64;
            cur_conns += snap.current_conns;
        }
    }

    #[allow(unused_mut)]
    let mut config = V2SystemInfoConfig {
        bind_port: snap.bind_port,
        vhost_http_port: snap.vhost_http_port,
        vhost_https_port: snap.vhost_https_port,
        tcpmux_httpconnect_port: snap.tcpmux_httpconnect_port,
        #[cfg(feature = "kcp")]
        kcp_bind_port: snap.kcp_bind_port,
        #[cfg(feature = "quic")]
        quic_bind_port: snap.quic_bind_port,
        subdomain_host: snap.subdomain_host.clone(),
        max_pool_count: snap.max_pool_count,
        max_ports_per_client: snap.max_ports_per_client,
        heartbeat_timeout: snap.heartbeat_timeout,
        allow_ports_str: snap.allow_ports_str.clone(),
        tls_force: snap.tls_force,
    };
    // Ensure the struct has all fields when features are off
    #[cfg(not(feature = "kcp"))] { let _ = &mut config; }
    #[cfg(not(feature = "quic"))] { let _ = &mut config; }

    Json(V2SystemInfoResp {
        version: env!("CARGO_PKG_VERSION").to_string(),
        config,
        status: V2SystemInfoStatus {
            total_traffic_in: total_in,
            total_traffic_out: total_out,
            cur_conns,
            client_counts: client_count,
            proxy_type_counts,
        },
    })
}

async fn handle_v2_system_prune(
    State(state): State<Arc<AppState>>,
    Query(q): Query<PruneQuery>,
) -> Result<Json<V2SystemPruneResp>, (StatusCode, Json<V2Error>)> {
    if q.prune_type != "offline_proxies" {
        return Err(v2_err(StatusCode::BAD_REQUEST, "type must be offline_proxies"));
    }

    let all = state.proxy_manager.list().await;
    let before = all.len();
    let ctl_map = state.run_id_to_ctl_tx.read().await;
    let mut cleared = 0usize;
    for p in &all {
        if let Some(run_id) = state.proxy_manager.get_run_id(&p.name).await {
            if !ctl_map.contains_key(&run_id) {
                state.proxy_manager.remove(&p.name).await;
                cleared += 1;
            }
        }
    }
    drop(ctl_map);

    Ok(Json(V2SystemPruneResp { prune_type: q.prune_type, cleared, total: before }))
}

async fn handle_v2_users(
    State(state): State<Arc<AppState>>,
    Query(q): Query<UserQuery>,
) -> Result<Json<V2PageResp<V2UserResp>>, (StatusCode, Json<V2Error>)> {
    let (page, size) = parse_page(q.page, q.page_size)?;

    let ctl_map = state.run_id_to_ctl_tx.read().await;
    let proxies = state.proxy_manager.list().await;

    // Build per-user stats from proxy data.
    let mut user_map: HashMap<String, V2UserResp> = HashMap::new();
    for p in &proxies {
        let user = if p.user.is_empty() { String::new() } else { p.user.clone() };
        let entry = user_map.entry(user.clone()).or_insert_with(|| V2UserResp {
            user: user.clone(),
            client_count: 0,
            proxy_count: 0,
        });
        entry.proxy_count += 1;
    }
    // Count clients per user. Each control connection maps to one client.
    // Clients are attributed to their login user (ControlTx.user).
    for (run_id, _ctl) in ctl_map.iter() {
        let proxies = state.proxy_manager.list_client(run_id).await;
        if let Some(first_proxy) = proxies.first() {
            let user = if first_proxy.user.is_empty() { String::new() } else { first_proxy.user.clone() };
            let entry = user_map.entry(user.clone()).or_insert_with(|| V2UserResp {
                user: user.clone(),
                client_count: 0,
                proxy_count: 0,
            });
            entry.client_count += 1;
        }
    }
    drop(ctl_map);

    let mut items: Vec<V2UserResp> = user_map.into_values().collect();
    items.sort_by(|a, b| a.user.cmp(&b.user));

    if let Some(ref search) = q.q {
        let s = search.to_lowercase();
        items.retain(|u| u.user.to_lowercase().contains(&s));
    }

    Ok(Json(paginate(items, page, size)))
}

async fn handle_v2_clients(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ClientQuery>,
) -> Result<Json<V2PageResp<V2ClientEntry>>, (StatusCode, Json<V2Error>)> {
    let (page, size) = parse_page(q.page, q.page_size)?;
    validate_status(q.status.as_deref().unwrap_or(""))?;

    let ctl_map = state.run_id_to_ctl_tx.read().await;
    let mut items = Vec::new();

    for (run_id, ctl) in ctl_map.iter() {
        let online = true; // entries in the map are online
        if !match_status(online, q.status.as_deref().unwrap_or("")) {
            continue;
        }

        let proxies = state.proxy_manager.list_client_proxy_names(run_id).await;
        let client_addr = ctl.client_addr.map(|a| a.to_string());
        let login_secs = ctl.login_time_unix as u64;

        // User filter: match against proxies registered by this client.
        if let Some(ref user_filter) = q.user {
            if !user_filter.is_empty() {
                let has_matching = state.proxy_manager.list_client(run_id).await
                    .iter()
                    .any(|p| p.user == *user_filter);
                if !has_matching { continue; }
            }
        }
        if let Some(ref rid) = q.run_id { if *rid != *run_id { continue; } }
        if let Some(ref cid) = q.client_id { if *cid != *run_id { continue; } }

        let proxy_count = proxies.len();
        let entry = V2ClientEntry {
            run_id: run_id.clone(),
            client_addr,
            online,
            login_time_secs: login_secs,
            proxy_count,
            proxies,
            pool_size: ctl.pool_stats.pool_size.load(Ordering::Relaxed),
            pending_requests: ctl.pool_stats.pending_requests.load(Ordering::Relaxed),
        };

        if let Some(ref search) = q.q {
            if !match_search(search, &[&entry.run_id, entry.client_addr.as_deref().unwrap_or("")]) {
                continue;
            }
        }

        items.push(entry);
    }
    drop(ctl_map);

    items.sort_by(|a, b| a.run_id.cmp(&b.run_id));
    Ok(Json(paginate(items, page, size)))
}

async fn handle_v2_client_detail(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Json<V2ClientDetailResp>, (StatusCode, Json<V2Error>)> {
    let key = percent_decode_path(&key)?;

    let ctl_map = state.run_id_to_ctl_tx.read().await;

    // Find by run_id first, then by client_addr
    let (run_id, ctl) = if let Some(ctl) = ctl_map.get(&key) {
        (key.clone(), ctl.clone())
    } else if let Some((rid, ctl)) = ctl_map.iter().find(|(_, c)| {
        c.client_addr.map(|a| a.to_string()) == Some(key.clone())
    }) {
        (rid.clone(), ctl.clone())
    } else {
        return Err(v2_err(StatusCode::NOT_FOUND, format!("client {key} not found")));
    };

    let proxies = state.proxy_manager.list_client_proxy_names(&run_id).await;
    let proxy_infos = state.proxy_manager.list_client(&run_id).await;
    let mut cur_conns: i64 = 0;
    for p in &proxy_infos {
        if let Some(m) = state.proxy_metrics.get(&p.name).await {
            cur_conns += m.snapshot().current_conns;
        }
    }

    let client_addr = ctl.client_addr.map(|a| a.to_string());
    let info = V2ClientEntry {
        run_id: run_id.clone(),
        client_addr,
        online: true,
        login_time_secs: ctl.login_time_unix as u64,
        proxy_count: proxies.len(),
        proxies: proxies.clone(),
        pool_size: ctl.pool_stats.pool_size.load(Ordering::Relaxed),
        pending_requests: ctl.pool_stats.pending_requests.load(Ordering::Relaxed),
    };

    Ok(Json(V2ClientDetailResp {
        info,
        status: V2ClientStatus {
            phase: "online".into(),
            cur_conns,
            proxy_count: proxy_infos.len() as i64,
        },
    }))
}

async fn handle_v2_proxies(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ProxyQuery>,
) -> Result<Json<V2PageResp<V2ProxyResp>>, (StatusCode, Json<V2Error>)> {
    let (page, size) = parse_page(q.page, q.page_size)?;
    validate_status(q.status.as_deref().unwrap_or(""))?;
    validate_type(q.proxy_type.as_deref().unwrap_or(""))?;

    let all = state.proxy_manager.list().await;
    let ctl_map = state.run_id_to_ctl_tx.read().await;
    let mut items = Vec::new();

    for p in &all {
        if let Some(ref pt) = q.proxy_type { if p.proxy_type != *pt { continue; } }

        let online = ctl_map.contains_key(&p.run_id);
        if !match_status(online, q.status.as_deref().unwrap_or("")) { continue; }

        // User filter
        if let Some(ref u) = q.user {
            if !u.is_empty() && p.user != *u {
                continue;
            }
        }

        if let Some(ref cid) = q.client_id { if p.run_id != *cid { continue; } }

        let spec = proxy_spec(p);
        let (today_in, today_out, cur_conns) = state.proxy_metrics.get(&p.name).await
            .map(|m| {
                let s = m.snapshot();
                let (tin, tout) = m.daily.snapshot();
                (tin[0], tout[0], s.current_conns)
            })
            .unwrap_or((0, 0, 0));

        let resp = V2ProxyResp {
            name: p.name.clone(),
            user: p.user.clone(),
            client_id: p.run_id.clone(),
            spec,
            status: V2ProxyStatus {
                phase: if online { "online" } else { "offline" }.into(),
                today_traffic_in: today_in,
                today_traffic_out: today_out,
                cur_conns,
                last_start_at: 0,
                last_close_at: 0,
            },
        };

        if let Some(ref search) = q.q {
            if !match_search(search, &[&resp.name, &resp.spec.proxy_type, &resp.client_id, &resp.status.phase]) {
                continue;
            }
        }

        items.push(resp);
    }
    drop(ctl_map);

    items.sort_by(|a, b| a.spec.proxy_type.cmp(&b.spec.proxy_type).then_with(|| a.name.cmp(&b.name)));
    Ok(Json(paginate(items, page, size)))
}

async fn handle_v2_proxy_detail(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<V2ProxyResp>, (StatusCode, Json<V2Error>)> {
    let name = percent_decode_path(&name)?;

    let p = state.proxy_manager.get(&name).await
        .ok_or_else(|| v2_err(StatusCode::NOT_FOUND, "no proxy info found"))?;

    let online = state.run_id_to_ctl_tx.read().await.contains_key(&p.run_id);

    let (today_in, today_out, cur_conns) = state.proxy_metrics.get(&p.name).await
        .map(|m| {
            let s = m.snapshot();
            let (tin, tout) = m.daily.snapshot();
            (tin[0], tout[0], s.current_conns)
        })
        .unwrap_or((0, 0, 0));

    Ok(Json(V2ProxyResp {
        name: p.name.clone(),
        user: p.user.clone(),
        client_id: p.run_id.clone(),
        spec: proxy_spec(&p),
        status: V2ProxyStatus {
            phase: if online { "online" } else { "offline" }.into(),
            today_traffic_in: today_in,
            today_traffic_out: today_out,
            cur_conns,
            last_start_at: 0,
            last_close_at: 0,
        },
    }))
}

async fn handle_v2_proxy_traffic(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<V2ProxyTrafficResp>, (StatusCode, Json<V2Error>)> {
    let name = percent_decode_path(&name)?;

    let p = state.proxy_manager.get(&name).await
        .ok_or_else(|| v2_err(StatusCode::NOT_FOUND, "no proxy info found"))?;

    let history = if let Some(m) = state.proxy_metrics.get(&p.name).await {
        let (tin, tout) = m.daily.snapshot();
        let today_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        (0..7).map(|age| {
            let date = format_date_ymd(today_secs - (age as i64) * 86400);
            V2TrafficPoint {
                date,
                traffic_in: tin[age as usize] as i64,
                traffic_out: tout[age as usize] as i64,
            }
        }).collect()
    } else {
        Vec::new()
    };

    Ok(Json(V2ProxyTrafficResp {
        name: p.name.clone(),
        unit: "bytes".into(),
        granularity: "day".into(),
        history,
    }))
}

// ── Route registration ───────────────────────────────────────────────

/// Register v2 API routes on the given router. Call from `run_dashboard()`.
pub fn v2_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v2/system/info", get(handle_v2_system_info))
        .route("/api/v2/system/prune", post(handle_v2_system_prune))
        .route("/api/v2/users", get(handle_v2_users))
        .route("/api/v2/clients", get(handle_v2_clients))
        .route("/api/v2/clients/{key}", get(handle_v2_client_detail))
        .route("/api/v2/proxies", get(handle_v2_proxies))
        .route("/api/v2/proxies/{name}", get(handle_v2_proxy_detail))
        .route("/api/v2/proxies/{name}/traffic", get(handle_v2_proxy_traffic))
}
