use std::sync::Arc;
use axum::{Router, Json, extract::{State, Path}, response::Html, routing::get};
use serde::Serialize;
use crate::service::AppState;
use frp_core::admin_auth::apply_admin_auth;
use frp_core::metrics::MetricsSnapshot;

#[derive(Serialize)]
struct StatusResponse {
    version: String,
    uptime_secs: u64,
    client_count: usize,
    proxy_count: usize,
}

#[derive(Serialize)]
struct ProxyEntry {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    status: String,
    remote_port: Option<u16>,
    local_addr: Option<String>,
    traffic_in: u64,
    traffic_out: u64,
}

#[derive(Serialize)]
struct ProxyDetail {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    status: String,
    run_id: Option<String>,
    remote_port: Option<u16>,
    local_addr: Option<String>,
    use_encryption: bool,
    use_compression: bool,
    custom_domains: Vec<String>,
    multiplexer: String,
    group: String,
    traffic: MetricsSnapshot,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// --- Handlers ---

async fn handle_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let uptime = state.dashboard_start.elapsed().as_secs();
    let client_count = state.run_id_to_ctl_tx.read().await.len();
    let proxies = state.proxy_manager.list().await;
    Json(StatusResponse {
        version: frp_core::VERSION.to_string(),
        uptime_secs: uptime,
        client_count,
        proxy_count: proxies.len(),
    })
}

async fn handle_proxies(State(state): State<Arc<AppState>>) -> Json<Vec<ProxyEntry>> {
    let proxies = state.proxy_manager.list().await;
    let mut entries = Vec::new();
    for p in &proxies {
        let online = state.run_id_to_ctl_tx.read().await.contains_key(&p.run_id);
        let traffic = state.proxy_metrics.get(&p.name).await
            .map(|m| m.snapshot())
            .unwrap_or_else(|| MetricsSnapshot {
                bytes_in: 0, bytes_out: 0, current_conns: 0, total_conns: 0,
            });
        entries.push(ProxyEntry {
            name: p.name.clone(),
            proxy_type: p.proxy_type.clone(),
            status: if online { "online".into() } else { "offline".into() },
            remote_port: p.remote_port,
            local_addr: p.local_addr.clone(),
            traffic_in: traffic.bytes_in,
            traffic_out: traffic.bytes_out,
        });
    }
    Json(entries)
}

async fn handle_proxy_detail(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<ProxyDetail>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let proxy = state.proxy_manager.get(&name).await
        .ok_or_else(|| (
            axum::http::StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: "proxy not found".into() }),
        ))?;

    let online = state.run_id_to_ctl_tx.read().await.contains_key(&proxy.run_id);
    let traffic = state.proxy_metrics.get(&name).await
        .map(|m| m.snapshot())
        .unwrap_or_else(|| MetricsSnapshot {
            bytes_in: 0, bytes_out: 0, current_conns: 0, total_conns: 0,
        });

    Ok(Json(ProxyDetail {
        name: proxy.name.clone(),
        proxy_type: proxy.proxy_type.clone(),
        status: if online { "online".into() } else { "offline".into() },
        run_id: Some(proxy.run_id.clone()),
        remote_port: proxy.remote_port,
        local_addr: proxy.local_addr.clone(),
        use_encryption: proxy.use_encryption,
        use_compression: proxy.use_compression,
        custom_domains: Vec::new(),
        multiplexer: String::new(),
        group: proxy.group.unwrap_or_default(),
        traffic,
    }))
}

async fn handle_proxy_traffic(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<MetricsSnapshot>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    // Verify proxy exists
    let _proxy = state.proxy_manager.get(&name).await
        .ok_or_else(|| (
            axum::http::StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: "proxy not found".into() }),
        ))?;

    let traffic = state.proxy_metrics.get(&name).await
        .map(|m| m.snapshot())
        .unwrap_or_else(|| MetricsSnapshot {
            bytes_in: 0, bytes_out: 0, current_conns: 0, total_conns: 0,
        });

    Ok(Json(traffic))
}

async fn handle_root() -> Html<String> {
    Html(format!(r##"<!DOCTYPE html>
<html><head><title>frp-rs Dashboard</title>
<style>
body{{font-family:sans-serif;margin:2em;background:#111;color:#eee}}
h1{{color:#4caf50}}
table{{border-collapse:collapse;width:100%}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid #333}}
th{{background:#222}}
.card{{background:#1a1a2e;padding:1em;border-radius:8px;margin:1em 0}}
pre{{background:#222;padding:1em;border-radius:4px}}
</style></head><body>
<h1>frp-rs v{}</h1>
<div class=card><pre id=status>Loading...</pre></div>
<div class=card><table id=proxies><tr><th>Name</th><th>Type</th><th>Status</th><th>Port</th><th>Traffic In</th><th>Traffic Out</th></tr></table></div>
<script>
async function load(){{try{{
let s=await fetch('/api/status');let d=await s.json();
document.getElementById('status').textContent=
  'Uptime: '+d.uptime_secs+'s | Clients: '+d.client_count+' | Proxies: '+d.proxy_count;
let p=await fetch('/api/proxies');let px=await p.json();
let rows=px.map(x=>'<tr><td><a href="#" onclick="loadDetail(\''+x.name+'\')">'+x.name+'</a></td><td>'+x.type+'</td><td>'+x.status+'</td><td>'+(x.remote_port||'-')+'</td><td>'+formatBytes(x.traffic_in)+'</td><td>'+formatBytes(x.traffic_out)+'</td></tr>').join('');
document.getElementById('proxies').innerHTML='<tr><th>Name</th><th>Type</th><th>Status</th><th>Port</th><th>Traffic In</th><th>Traffic Out</th></tr>'+rows;
}}catch(e){{setTimeout(load,1000)}}}}
async function loadDetail(name){{try{{
let r=await fetch('/api/proxy/'+name);let d=await r.json();
alert(JSON.stringify(d,null,2));
}}catch(e){{}}}}
function formatBytes(b){{if(b<1024)return b+'B';if(b<1048576)return (b/1024).toFixed(1)+'KB';return (b/1048576).toFixed(1)+'MB'}}
load();setInterval(load,5000);
</script></body></html>"##, frp_core::VERSION))
}

pub async fn run_dashboard(
    addr: String,
    state: Arc<AppState>,
    auth_user: String,
    auth_password: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // API routes
    let api_routes = Router::new()
        .route("/api/status", get(handle_status))
        .route("/api/proxies", get(handle_proxies))
        .route("/api/proxy/:name", get(handle_proxy_detail))
        .route("/api/proxy/:name/traffic", get(handle_proxy_traffic));

    // Apply auth to API routes only (not HTML page)
    let api_routes = apply_admin_auth(api_routes, &auth_user, &auth_password);

    let app = Router::new()
        .route("/", get(handle_root))
        .merge(api_routes)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Dashboard listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
