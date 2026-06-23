use std::sync::Arc;
use std::net::SocketAddr;
use axum::{Router, Json, extract::State, response::Html};
use serde::Serialize;
use crate::service::AppState;

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
    proxy_type: String,
    remote_port: Option<u16>,
    local_addr: Option<String>,
}

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
    let entries: Vec<ProxyEntry> = proxies.into_iter().map(|p| ProxyEntry {
        name: p.name,
        proxy_type: p.proxy_type,
        remote_port: p.remote_port,
        local_addr: p.local_addr,
    }).collect();
    Json(entries)
}

async fn handle_root() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html>
<html><head><title>frp-rs Dashboard</title>
<style>
body{font-family:sans-serif;margin:2em;background:#111;color:#eee}
h1{color:#4caf50}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:8px;border-bottom:1px solid #333}
th{background:#222}
.card{background:#1a1a2e;padding:1em;border-radius:8px;margin:1em 0}
pre{background:#222;padding:1em;border-radius:4px}
</style></head><body>
<h1>frp-rs v0.60.0</h1>
<div class=card><pre id=status>Loading...</pre></div>
<div class=card><table id=proxies><tr><th>Name</th><th>Type</th><th>Remote Port</th><th>Local</th></tr></table></div>
<script>
async function load(){try{
let s=await fetch('/api/status');let d=await s.json();
document.getElementById('status').textContent=
  'Uptime: '+d.uptime_secs+'s | Clients: '+d.client_count+' | Proxies: '+d.proxy_count;
let p=await fetch('/api/proxies');let px=await p.json();
document.getElementById('proxies').innerHTML='<tr><th>Name</th><th>Type</th><th>Remote Port</th><th>Local</th></tr>'+
  px.map(x=>'<tr><td>'+x.name+'</td><td>'+x.proxy_type+'</td><td>'+(x.remote_port||'-')+'</td><td>'+(x.local_addr||'-')+'</td></tr>').join('');
}catch(e){setTimeout(load,1000)}}
load();setInterval(load,5000);
</script></body></html>"#)
}

pub async fn run_dashboard(addr: String, state: Arc<AppState>) -> Result<(), Box<dyn std::error::Error>> {
    let addr2 = addr.clone();
    let app = Router::new()
        .route("/", axum::routing::get(handle_root))
        .route("/api/status", axum::routing::get(handle_status))
        .route("/api/proxies", axum::routing::get(handle_proxies))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Dashboard listening on {}", addr2);
    axum::serve(listener, app).await?;
    Ok(())
}
