use std::sync::Arc;
use axum::{Router, Json, extract::State, response::Html, response::IntoResponse};
use serde::Serialize;
use crate::service::AppState;

#[derive(Serialize)]
struct StatusResponse {
    version: String,
    uptime_secs: u64,
    client_count: i64,
    proxy_count: i64,
    connection_count: i64,
    traffic_in: u64,
    traffic_out: u64,
}

#[derive(Serialize)]
struct ProxyEntry {
    name: String,
    proxy_type: String,
    remote_port: Option<u16>,
    local_addr: Option<String>,
    traffic_in: u64,
    traffic_out: u64,
    connections: i64,
}

async fn handle_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let uptime = state.dashboard_start.elapsed().as_secs();

    let stats = state.metrics.as_ref().map(|m| m.mem_backend().server_stats());
    let (client_count, proxy_count, connection_count, traffic_in, traffic_out) = match stats {
        Some(s) => (s.client_count, s.proxy_count, s.connection_count, s.traffic_in, s.traffic_out),
        None => {
            let client_count = state.run_id_to_ctl_tx.read().await.len() as i64;
            let proxy_count = state.proxy_manager.list().await.len() as i64;
            (client_count, proxy_count, 0i64, 0u64, 0u64)
        }
    };

    Json(StatusResponse {
        version: frp_core::VERSION.to_string(),
        uptime_secs: uptime,
        client_count,
        proxy_count,
        connection_count,
        traffic_in,
        traffic_out,
    })
}

async fn handle_proxies(State(state): State<Arc<AppState>>) -> Json<Vec<ProxyEntry>> {
    // Use mem backend stats when available (includes traffic data)
    let mem_list = state.metrics.as_ref()
        .map(|m| m.mem_backend().proxy_stats_list())
        .unwrap_or_default();

    if !mem_list.is_empty() {
        let entries: Vec<ProxyEntry> = mem_list.into_iter().map(|p| ProxyEntry {
            name: p.name,
            proxy_type: p.proxy_type,
            remote_port: None,
            local_addr: None,
            traffic_in: p.traffic_in,
            traffic_out: p.traffic_out,
            connections: p.connections,
        }).collect();
        return Json(entries);
    }

    // Fallback: read from proxy_manager when no metrics data
    let proxies = state.proxy_manager.list().await;
    let entries: Vec<ProxyEntry> = proxies.into_iter().map(|p| ProxyEntry {
        name: p.name,
        proxy_type: p.proxy_type,
        remote_port: p.remote_port,
        local_addr: p.local_addr,
        traffic_in: 0,
        traffic_out: 0,
        connections: 0,
    }).collect();
    Json(entries)
}

async fn handle_metrics() -> impl IntoResponse {
    let body = crate::metrics::prom::render_metrics_text();
    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

async fn handle_root() -> Html<String> {
    Html(format!(r#"<!DOCTYPE html>
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
<div class=card><table id=proxies><tr><th>Name</th><th>Type</th><th>Remote Port</th><th>Local</th></tr></table></div>
<script>
async function load(){{try{{
let s=await fetch('/api/status');let d=await s.json();
document.getElementById('status').textContent=
  'Uptime: '+d.uptime_secs+'s | Clients: '+d.client_count+' | Proxies: '+d.proxy_count
  +' | Conns: '+d.connection_count+' | In: '+d.traffic_in+' | Out: '+d.traffic_out;
let p=await fetch('/api/proxies');let px=await p.json();
document.getElementById('proxies').innerHTML='<tr><th>Name</th><th>Type</th><th>Remote Port</th><th>Local</th><th>Traffic In</th><th>Traffic Out</th><th>Conns</th></tr>'+
  px.map(x=>'<tr><td>'+x.name+'</td><td>'+x.proxy_type+'</td><td>'+(x.remote_port||'-')+'</td><td>'+(x.local_addr||'-')+'</td><td>'+x.traffic_in+'</td><td>'+x.traffic_out+'</td><td>'+x.connections+'</td></tr>').join('');
}}catch(e){{setTimeout(load,1000)}}}}
load();setInterval(load,5000);
</script></body></html>"#, frp_core::VERSION))
}

pub async fn run_dashboard(addr: String, state: Arc<AppState>) -> Result<(), Box<dyn std::error::Error>> {
    let addr2 = addr.clone();
    let enable_prometheus = state.metrics.as_ref()
        .map(|m| m.backend_count() > 1)
        .unwrap_or(false);

    let mut app = Router::new()
        .route("/", axum::routing::get(handle_root))
        .route("/api/status", axum::routing::get(handle_status))
        .route("/api/proxies", axum::routing::get(handle_proxies));

    if enable_prometheus {
        app = app.route("/metrics", axum::routing::get(handle_metrics));
    }

    let app = app.with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Dashboard listening on {}", addr2);
    axum::serve(listener, app).await?;
    Ok(())
}
