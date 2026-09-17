# Dashboard HTML Upgrade — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace minimal dashboard HTML with a full admin panel (monitoring + proxy management) in a single `dashboard.html` file.

**Architecture:** Single `dashboard.html` embedded via `include_str!()` in `dashboard.rs`. No Rust changes, no new dependencies, no build step. Modern Clean visual style (system font, purple/cyan/amber accents, #0f0f1a background). Canvas charts hand-rolled (~100 lines vanilla JS). 5s polling with countdown indicator.

**Tech Stack:** HTML5, CSS3, vanilla JavaScript (ES6), `<canvas>` API. Served by existing axum `handle_root()` handler via `include_str!()`.

---

## File Structure

| File | Action |
|------|--------|
| `frp-server/src/dashboard.html` | Complete rewrite (~500 lines) |

No other files changed.

---

### Task 1: Write the complete dashboard.html

**Files:**
- Modify: `frp-server/src/dashboard.html` — full rewrite

- [ ] **Step 1: Replace dashboard.html with new implementation**

Write the following content to `frp-server/src/dashboard.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>frp-rs Dashboard</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: system-ui, -apple-system, sans-serif;
  background: #0f0f1a;
  color: #e0e0e0;
  padding: 20px;
  min-height: 100vh;
}
h2 { font-size: 13px; font-weight: 600; color: #8b8baa; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 10px; }

/* Header */
.header {
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid #2d2d4a;
}
.header-left { font-size: 18px; font-weight: 700; color: #e0e0e0; }
.header-left span { color: #a78bfa; }
.header-right { font-size: 12px; color: #8b8baa; display: flex; gap: 16px; align-items: center; }
.header-right .countdown { color: #6b7280; font-family: ui-monospace, SF Mono, monospace; font-size: 11px; }

/* Cards */
.card {
  background: #1a1a2e; border: 1px solid #2d2d4a; border-radius: 8px;
  padding: 16px; margin-bottom: 12px;
}

/* Stat row */
.stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
.stat-card {
  background: #1a1a2e; border: 1px solid #2d2d4a; border-radius: 8px;
  padding: 16px; text-align: center;
}
.stat-card .num { font-size: 28px; font-weight: 600; line-height: 1.2; }
.stat-card .label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: #8b8baa; margin-top: 4px; }
.stat-card.clients .num { color: #a78bfa; }
.stat-card.proxies .num { color: #60a5fa; }
.stat-card.traffic-in .num { color: #f59e0b; }
.stat-card.traffic-out .num { color: #f472b6; }

/* Tables */
table { width: 100%; border-collapse: collapse; }
th {
  font-size: 10px; font-weight: 600; color: #8b8baa; text-transform: uppercase;
  letter-spacing: 0.5px; text-align: left; padding: 6px 8px; border-bottom: 1px solid #2d2d4a;
}
td { padding: 7px 8px; border-bottom: 1px solid #1e1e32; font-size: 13px; }
tr:hover td { background: rgba(255,255,255,0.02); }
.proxy-row { cursor: pointer; transition: background 0.15s; }
.proxy-row.expanded td { background: rgba(167,139,250,0.06); border-bottom-color: #2d2d4a; }

/* Status dots */
.dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; margin-right: 5px; vertical-align: middle; }
.dot.online { background: #34d399; }
.dot.offline { background: #f87171; }

/* Detail panel */
.detail-row td { padding: 0; border-bottom: 1px solid #2d2d4a; }
.detail-panel {
  display: flex; gap: 20px; padding: 14px 16px;
  background: rgba(167,139,250,0.04); border-left: 2px solid #a78bfa;
}
.detail-panel .config { flex: 1; }
.detail-panel .config dt { font-size: 10px; color: #8b8baa; text-transform: uppercase; margin-top: 6px; }
.detail-panel .config dd { font-size: 13px; color: #e0e0e0; margin-left: 0; }
.detail-panel .config dd.mono { font-family: ui-monospace, SF Mono, monospace; font-size: 11px; color: #8b8baa; }
.detail-panel .traffic-panel { flex: 1; display: flex; flex-direction: column; align-items: center; }
.detail-panel .conn-info { font-size: 11px; color: #8b8baa; margin-top: 6px; text-align: center; }

/* Store form */
.store-grid { display: flex; gap: 16px; }
.store-form { flex: 1; }
.store-list { flex: 1; border-left: 1px solid #2d2d4a; padding-left: 16px; }
.form-row { display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-end; }
.form-group { display: flex; flex-direction: column; gap: 3px; }
.form-group label { font-size: 10px; color: #8b8baa; text-transform: uppercase; }
.form-group input, .form-group select {
  background: #0f0f1a; border: 1px solid #2d2d4a; border-radius: 4px;
  color: #e0e0e0; padding: 6px 10px; font-size: 13px; font-family: inherit;
}
.form-group input:focus, .form-group select:focus { outline: none; border-color: #a78bfa; }

/* Buttons */
.btn {
  padding: 6px 14px; border: none; border-radius: 4px; font-size: 12px;
  font-weight: 600; cursor: pointer; font-family: inherit; transition: background 0.15s;
}
.btn-primary { background: #a78bfa; color: #0f0f1a; }
.btn-primary:hover { background: #c4b5fd; }
.btn-danger { background: transparent; color: #f87171; border: 1px solid #f87171; }
.btn-danger:hover { background: rgba(248,113,113,0.15); }
.btn-sm { padding: 3px 10px; font-size: 11px; }

/* Toast */
.toast {
  position: fixed; top: 16px; right: 16px; padding: 10px 18px; border-radius: 6px;
  font-size: 13px; z-index: 999; animation: slideIn 0.25s ease; max-width: 360px;
}
.toast.success { background: #065f46; color: #d1fae5; border: 1px solid #059669; }
.toast.error { background: #7f1d1d; color: #fee2e2; border: 1px solid #dc2626; }
@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

/* Expand arrow */
.expand-arrow { color: #6b7280; font-size: 11px; transition: transform 0.2s; display: inline-block; }
.expand-arrow.open { transform: rotate(90deg); }

/* Store item */
.store-item {
  display: flex; justify-content: space-between; align-items: center;
  padding: 6px 0; border-bottom: 1px solid #1e1e32; font-size: 12px;
}
.store-item:last-child { border-bottom: none; }

/* Muted text */
.muted { color: #6b7280; }
.mono { font-family: ui-monospace, SF Mono, monospace; }
.text-right { text-align: right; }
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="header-left">frp-rs <span>Dashboard</span></div>
  <div class="header-right">
    <span>v{version}</span>
    <span>Uptime: <strong id="uptime">--</strong></span>
    <span class="countdown">Refresh in <span id="countdown">5</span>s</span>
  </div>
</div>

<!-- Stat Cards -->
<div class="stats">
  <div class="stat-card clients">
    <div class="num" id="stat-clients">--</div>
    <div class="label">Clients Online</div>
  </div>
  <div class="stat-card proxies">
    <div class="num" id="stat-proxies">--</div>
    <div class="label">Proxies Active</div>
  </div>
  <div class="stat-card traffic-in">
    <div class="num" id="stat-in">--</div>
    <div class="label">Traffic In</div>
  </div>
  <div class="stat-card traffic-out">
    <div class="num" id="stat-out">--</div>
    <div class="label">Traffic Out</div>
  </div>
</div>

<!-- Traffic Chart -->
<div class="card">
  <h2>Traffic (last 50s)</h2>
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
    <span style="font-size:11px;color:#60a5fa">■ In</span>
    <span style="font-size:11px;color:#f59e0b">■ Out</span>
  </div>
  <canvas id="trafficChart" width="600" height="120" style="width:100%;height:120px"></canvas>
</div>

<!-- Proxy Table -->
<div class="card">
  <h2>Proxies</h2>
  <table>
    <thead>
      <tr>
        <th>Name</th><th>Type</th><th>Status</th><th>Port</th>
        <th>Local Addr</th><th>In</th><th>Out</th><th>Conn</th><th></th>
      </tr>
    </thead>
    <tbody id="proxy-tbody"></tbody>
  </table>
</div>

<!-- Client Table -->
<div class="card">
  <h2>Clients</h2>
  <table>
    <thead>
      <tr><th>Run ID</th><th>Address</th><th>Uptime</th><th>Proxies</th></tr>
    </thead>
    <tbody id="client-tbody"></tbody>
  </table>
</div>

<!-- Store -->
<div class="card">
  <h2>Proxy Store</h2>
  <div class="store-grid">
    <div class="store-form">
      <div style="font-size:11px;color:#8b8baa;margin-bottom:8px;text-transform:uppercase">Create New</div>
      <div class="form-row">
        <div class="form-group">
          <label>Name *</label>
          <input id="store-name" placeholder="my-proxy" style="width:110px">
        </div>
        <div class="form-group">
          <label>Type *</label>
          <select id="store-type" style="width:90px">
            <option value="">--</option>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="http">http</option>
            <option value="https">https</option>
            <option value="stcp">stcp</option>
            <option value="xtcp">xtcp</option>
            <option value="tcpmux">tcpmux</option>
            <option value="sudp">sudp</option>
          </select>
        </div>
        <div class="form-group">
          <label>Port</label>
          <input id="store-port" placeholder="0" style="width:70px">
        </div>
        <div class="form-group">
          <label>Local Addr</label>
          <input id="store-local" placeholder="127.0.0.1:3000" style="width:140px">
        </div>
        <button class="btn btn-primary" onclick="createProxy()">Create</button>
      </div>
    </div>
    <div class="store-list">
      <div style="font-size:11px;color:#8b8baa;margin-bottom:8px;text-transform:uppercase">Stored Configs</div>
      <div id="store-items"><span class="muted" style="font-size:12px">Loading...</span></div>
    </div>
  </div>
</div>

<script>
// --- State ---
const HISTORY_LEN = 10;
let state = {
  proxies: [],
  clients: [],
  trafficHistory: [],  // [{bytesIn, bytesOut}, ...]
  expandedProxy: null,
  countdown: 5,
  storeConfigs: [],
};

// --- Helpers ---
function formatBytes(b) {
  if (b == null || b === 0) return '0 B';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

function formatDuration(secs) {
  if (!secs || secs < 0) return '--';
  let h = Math.floor(secs / 3600);
  let m = Math.floor((secs % 3600) / 60);
  let s = secs % 60;
  if (h > 0) return h + 'h ' + m + 'm';
  if (m > 0) return m + 'm ' + s + 's';
  return s + 's';
}

function truncate(s, n) { return s && s.length > n ? s.slice(0, n) + '...' : (s || '--'); }

function toast(msg, type) {
  let el = document.createElement('div');
  el.className = 'toast ' + (type || 'success');
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(function(){ el.remove(); }, 3000);
}

// --- Canvas Charts ---
function drawBarChart(canvas, data, width, height) {
  let ctx = canvas.getContext('2d');
  let dpr = window.devicePixelRatio || 1;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  canvas.style.width = width + 'px';
  canvas.style.height = height + 'px';
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);

  if (!data || data.length === 0) return;

  let barW = Math.max(2, Math.floor((width - 8) / data.length) - 2);
  let maxVal = 1;
  for (let i = 0; i < data.length; i++) {
    let v = Math.max(data[i].bytesIn || 0, data[i].bytesOut || 0);
    if (v > maxVal) maxVal = v;
  }
  let scale = (height - 8) / maxVal;

  for (let i = 0; i < data.length; i++) {
    let x = 4 + i * (barW + 2);
    // In bar (blue)
    let hIn = Math.max(1, (data[i].bytesIn || 0) * scale);
    ctx.fillStyle = '#60a5fa';
    ctx.fillRect(x, height - hIn - 2, barW / 2 - 1, hIn);
    // Out bar (amber)
    let hOut = Math.max(1, (data[i].bytesOut || 0) * scale);
    ctx.fillStyle = '#f59e0b';
    ctx.fillRect(x + barW / 2, height - hOut - 2, barW / 2 - 1, hOut);
  }
}

function drawSparkline(canvas, data, width, height) {
  let ctx = canvas.getContext('2d');
  let dpr = window.devicePixelRatio || 1;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  canvas.style.width = width + 'px';
  canvas.style.height = height + 'px';
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);

  if (!data || data.length < 2) {
    ctx.fillStyle = '#8b8baa';
    ctx.font = '11px system-ui';
    ctx.textAlign = 'center';
    ctx.fillText('Not enough data', width / 2, height / 2);
    return;
  }

  let maxVal = 1;
  for (let i = 0; i < data.length; i++) {
    let v = Math.max(data[i].bytesIn || 0, data[i].bytesOut || 0);
    if (v > maxVal) maxVal = v;
  }

  let pad = 4;
  let scaleX = (width - pad * 2) / (data.length - 1);
  let scaleY = (height - pad * 2) / maxVal;

  // Grid lines
  ctx.strokeStyle = '#2d2d4a';
  ctx.lineWidth = 0.5;
  for (let g = 0; g < 4; g++) {
    let y = pad + g * ((height - pad * 2) / 3);
    ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(width - pad, y); ctx.stroke();
  }

  function drawLine(series, color) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    let first = true;
    for (let i = 0; i < series.length; i++) {
      let x = pad + i * scaleX;
      let y = height - pad - (series[i] || 0) * scaleY;
      if (first) { ctx.moveTo(x, y); first = false; }
      else ctx.lineTo(x, y);
    }
    ctx.stroke();
  }

  drawLine(data.map(function(d){ return d.bytesIn || 0; }), '#60a5fa');
  drawLine(data.map(function(d){ return d.bytesOut || 0; }), '#f59e0b');
}

// --- Data Fetching ---
async function load() {
  try {
    let sResp = await fetch('/api/status');
    if (!sResp.ok) throw new Error('status ' + sResp.status);
    let status = await sResp.json();
    renderStats(status);

    let pResp = await fetch('/api/proxies');
    if (!pResp.ok) throw new Error('proxies ' + pResp.status);
    state.proxies = await pResp.json();
    renderProxies();

    // Update traffic history
    let totalIn = 0, totalOut = 0;
    for (let p of state.proxies) {
      totalIn += p.traffic_in || 0;
      totalOut += p.traffic_out || 0;
    }
    state.trafficHistory.push({ bytesIn: totalIn, bytesOut: totalOut });
    if (state.trafficHistory.length > HISTORY_LEN) state.trafficHistory.shift();
    renderTraffic();

    // If detail open, refresh it
    if (state.expandedProxy) {
      refreshDetail(state.expandedProxy);
    }
  } catch(e) {
    console.error('load error:', e);
  }
  state.countdown = 5;
}

async function loadClients() {
  try {
    let resp = await fetch('/api/clients');
    if (!resp.ok) throw new Error('clients ' + resp.status);
    state.clients = await resp.json();
    renderClients();
  } catch(e) {
    console.error('clients error:', e);
  }
}

async function loadStore() {
  try {
    let resp = await fetch('/api/store/proxies');
    if (!resp.ok) throw new Error('store ' + resp.status);
    state.storeConfigs = await resp.json();
    renderStore();
  } catch(e) {
    console.error('store error:', e);
  }
}

// --- Rendering ---
function renderStats(d) {
  document.getElementById('uptime').textContent = formatDuration(d.uptime_secs);
  document.getElementById('stat-clients').textContent = d.client_count;
  document.getElementById('stat-proxies').textContent = d.proxy_count;
  // Traffic totals computed in load()
}

function renderTraffic() {
  let canvas = document.getElementById('trafficChart');
  if (!canvas) return;
  let rect = canvas.parentElement.getBoundingClientRect();
  let w = Math.max(200, rect.width - 32);
  drawBarChart(canvas, state.trafficHistory, w, 120);

  // Update traffic stat cards
  let last = state.trafficHistory.length > 0 ? state.trafficHistory[state.trafficHistory.length - 1] : null;
  document.getElementById('stat-in').textContent = last ? formatBytes(last.bytesIn) : '--';
  document.getElementById('stat-out').textContent = last ? formatBytes(last.bytesOut) : '--';
}

function renderProxies() {
  let tbody = document.getElementById('proxy-tbody');
  if (state.proxies.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="muted" style="text-align:center;padding:20px">No proxies registered</td></tr>';
    return;
  }
  let rows = [];
  for (let i = 0; i < state.proxies.length; i++) {
    let p = state.proxies[i];
    let online = p.status === 'online';
    let isExpanded = state.expandedProxy === p.name;
    rows.push('<tr class="proxy-row' + (isExpanded ? ' expanded' : '') + '" onclick="toggleProxy(\'' + escAttr(p.name) + '\')">');
    rows.push('<td style="color:#e0e0e0">' + escHtml(p.name) + '</td>');
    rows.push('<td>' + escHtml(p.type) + '</td>');
    rows.push('<td><span class="dot ' + (online ? 'online' : 'offline') + '"></span>' + (online ? 'online' : 'offline') + '</td>');
    rows.push('<td>' + (p.remote_port || '--') + '</td>');
    rows.push('<td class="mono" style="font-size:11px">' + escHtml(p.local_addr || '--') + '</td>');
    rows.push('<td style="color:#60a5fa">' + formatBytes(p.traffic_in) + '</td>');
    rows.push('<td style="color:#f59e0b">' + formatBytes(p.traffic_out) + '</td>');
    rows.push('<td>' + (p.total_conns != null ? p.total_conns : '--') + '</td>');
    rows.push('<td><span class="expand-arrow' + (isExpanded ? ' open' : '') + '">▶</span></td>');
    rows.push('</tr>');
    if (isExpanded) {
      rows.push('<tr class="detail-row"><td colspan="9"><div class="detail-panel" id="detail-' + escAttr(p.name) + '">Loading...</div></td></tr>');
    }
  }
  tbody.innerHTML = rows.join('');
}

function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escAttr(s) {
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function toggleProxy(name) {
  if (state.expandedProxy === name) {
    collapseProxy();
  } else {
    await expandProxy(name);
  }
}

async function expandProxy(name) {
  state.expandedProxy = name;
  renderProxies(); // show expanded row placeholder
  await refreshDetail(name);
}

function collapseProxy() {
  state.expandedProxy = null;
  renderProxies();
}

async function refreshDetail(name) {
  let panel = document.getElementById('detail-' + escAttr(name));
  if (!panel) return;
  try {
    let dResp = await fetch('/api/proxy/' + encodeURIComponent(name));
    let tResp = await fetch('/api/proxy/' + encodeURIComponent(name) + '/traffic');
    if (!dResp.ok) { panel.innerHTML = '<span style="color:#f87171">Error loading detail</span>'; return; }
    let detail = await dResp.json();
    let traffic = tResp.ok ? await tResp.json() : null;

    panel.innerHTML =
      '<div class="config">' +
        '<dl>' +
          '<dt>Type</dt><dd>' + escHtml(detail.type) + '</dd>' +
          '<dt>Remote Port</dt><dd>' + (detail.remote_port || '--') + '</dd>' +
          '<dt>Local Addr</dt><dd class="mono">' + escHtml(detail.local_addr || '--') + '</dd>' +
          '<dt>Encryption</dt><dd style="color:' + (detail.use_encryption ? '#34d399' : '#f87171') + '">' + (detail.use_encryption ? 'yes' : 'no') + '</dd>' +
          '<dt>Compression</dt><dd style="color:' + (detail.use_compression ? '#34d399' : '#f87171') + '">' + (detail.use_compression ? 'yes' : 'no') + '</dd>' +
          '<dt>Group</dt><dd>' + escHtml(detail.group || '--') + '</dd>' +
          '<dt>Run ID</dt><dd class="mono">' + truncate(detail.run_id, 16) + '</dd>' +
        '</dl>' +
      '</div>' +
      '<div class="traffic-panel">' +
        '<canvas id="spark-' + escAttr(name) + '" width="220" height="80" style="width:220px;height:80px"></canvas>' +
        '<div class="conn-info">Connections: ' + (traffic ? traffic.current_conns : '--') + ' active &middot; ' + (traffic ? traffic.total_conns : '--') + ' total</div>' +
      '</div>';

    // If we had per-proxy history we'd draw sparkline here.
    // For now, draw a simple bar from current traffic snapshot.
    let sparkCanvas = document.getElementById('spark-' + escAttr(name));
    if (sparkCanvas && traffic) {
      let snapData = [{bytesIn: traffic.bytes_in || 0, bytesOut: traffic.bytes_out || 0}];
      drawBarChart(sparkCanvas, snapData, 220, 80);
    }
  } catch(e) {
    panel.innerHTML = '<span style="color:#f87171">Error: ' + escHtml(String(e)) + '</span>';
  }
}

function renderClients() {
  let tbody = document.getElementById('client-tbody');
  if (state.clients.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="muted" style="text-align:center;padding:20px">No clients connected</td></tr>';
    return;
  }
  let rows = [];
  for (let c of state.clients) {
    rows.push('<tr>');
    rows.push('<td class="mono" style="font-size:11px;color:#8b8baa">' + truncate(c.run_id, 16) + '</td>');
    rows.push('<td>' + escHtml(c.client_addr || '--') + '</td>');
    rows.push('<td>' + formatDuration(c.login_time_secs) + '</td>');
    rows.push('<td>' + (c.proxies && c.proxies.length > 0 ? escHtml(c.proxies.join(', ')) : '<span class="muted">none</span>') + '</td>');
    rows.push('</tr>');
  }
  tbody.innerHTML = rows.join('');
}

// --- Store Actions ---
async function createProxy() {
  let name = document.getElementById('store-name').value.trim();
  let type = document.getElementById('store-type').value;
  let port = document.getElementById('store-port').value.trim();
  let local = document.getElementById('store-local').value.trim();

  if (!name) { toast('Name is required', 'error'); return; }
  if (!type) { toast('Type is required', 'error'); return; }

  let body = { name: name, type: type };
  if (port) body.remote_port = parseInt(port, 10) || 0;
  if (local) body.local_addr = local;

  try {
    let resp = await fetch('/api/store/proxies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    let data = await resp.json();
    if (resp.ok) {
      toast('Created: ' + name, 'success');
      document.getElementById('store-name').value = '';
      document.getElementById('store-type').value = '';
      document.getElementById('store-port').value = '';
      document.getElementById('store-local').value = '';
      await loadStore();
    } else {
      toast(data.error || 'Create failed', 'error');
    }
  } catch(e) {
    toast('Network error: ' + e.message, 'error');
  }
}

async function deleteProxy(name) {
  if (!confirm('Delete proxy "' + name + '" from store?')) return;
  try {
    let resp = await fetch('/api/store/proxy/' + encodeURIComponent(name), { method: 'DELETE' });
    let data = await resp.json();
    if (resp.ok) {
      toast('Deleted: ' + name, 'success');
      await loadStore();
      // Reload proxy list since proxy was removed
      await load();
    } else {
      toast(data.error || 'Delete failed', 'error');
    }
  } catch(e) {
    toast('Network error: ' + e.message, 'error');
  }
}

function renderStore() {
  let container = document.getElementById('store-items');
  if (!state.storeConfigs || state.storeConfigs.length === 0) {
    container.innerHTML = '<span class="muted" style="font-size:12px">No stored configs</span>';
    return;
  }
  let items = [];
  for (let c of state.storeConfigs) {
    items.push(
      '<div class="store-item">' +
        '<span>' + escHtml(c.name) + ' <span class="muted">' + escHtml(c.type) + '</span>' +
        (c.remote_port ? ' :' + c.remote_port : '') + '</span>' +
        '<button class="btn btn-danger btn-sm" onclick="deleteProxy(\'' + escAttr(c.name) + '\')">Delete</button>' +
      '</div>'
    );
  }
  container.innerHTML = items.join('');
}

// --- Poll Loop ---
function countdownTick() {
  state.countdown--;
  document.getElementById('countdown').textContent = Math.max(0, state.countdown);
}

async function tick() {
  if (state.countdown <= 0) {
    await load();
    await loadClients();
    await loadStore();
  } else {
    countdownTick();
  }
}

// --- Init ---
load();
loadClients();
loadStore();
setInterval(tick, 1000);
</script>
</body>
</html>
```

- [ ] **Step 2: Verify file was written correctly**

```bash
wc -l frp-server/src/dashboard.html
```

Expected: ~450-500 lines.

---

### Task 2: Build and verify

**Files:** No changes — verification only.

- [ ] **Step 1: Build the workspace**

```bash
cargo build --workspace
```

Expected: Clean build, no errors.

- [ ] **Step 2: Run existing tests**

```bash
cargo test --workspace
```

Expected: All tests pass (no Rust changes, so existing test count unchanged).

- [ ] **Step 3: Run clippy**

```bash
cargo clippy --workspace
```

Expected: No new warnings.

- [ ] **Step 4: Create a minimal frps config for dashboard smoke test**

Write to `/tmp/frps-dash-test.toml`:

```toml
bind_addr = "0.0.0.0"
bind_port = 7999
auth.token = "test123"
dashboard.enable = true
dashboard.port = 7500
dashboard.user = "admin"
dashboard.pwd = "admin"
```

- [ ] **Step 5: Start frps with dashboard**

```bash
cargo run --bin frps -- -c /tmp/frps-dash-test.toml &
FRPS_PID=$!
sleep 2
```

- [ ] **Step 6: Verify dashboard serves HTML**

```bash
curl -s -u admin:admin http://localhost:7500/ | head -5
```

Expected: `<!DOCTYPE html>` and dashboard content.

- [ ] **Step 7: Verify /api/status returns JSON**

```bash
curl -s -u admin:admin http://localhost:7500/api/status | python3 -m json.tool
```

Expected: JSON with `version`, `uptime_secs`, `client_count`, `proxy_count` fields.

- [ ] **Step 8: Verify /api/proxies returns JSON array**

```bash
curl -s -u admin:admin http://localhost:7500/api/proxies | python3 -m json.tool
```

Expected: `[]` (empty array, no proxies registered yet).

- [ ] **Step 9: Stop frps**

```bash
kill $FRPS_PID
```

---

### Task 3: Commit

**Files:** Modified `frp-server/src/dashboard.html`

- [ ] **Step 1: Stage and commit**

```bash
git add frp-server/src/dashboard.html
git commit -m "feat: upgrade dashboard HTML with full admin panel

- Modern Clean visual style (system font, purple/cyan/amber accents)
- Stat cards (clients, proxies, traffic in/out)
- Canvas bar chart for traffic history (rolling 50s window)
- Proxy table with inline expandable detail panel
- Client table with run ID, address, uptime, proxy list
- Store section with create form and delete buttons
- 5s polling with countdown indicator
- Zero new dependencies, no Rust changes

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"