# Dashboard HTML Upgrade — Design Spec

**Date:** 2026-06-27
**Status:** approved

## Overview

Replace the current minimal dashboard HTML (30 lines, two cards, `alert()` for detail) with a full admin panel: monitoring + proxy management. Single file, zero new dependencies, no build step.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Tech | Single `dashboard.html`, `include_str!()` | Matches existing pattern. No build step, no Node toolchain. |
| Charts | `<canvas>` hand-rolled ~100 lines JS | Zero dependencies. Works offline (air-gapped deployments). |
| Updates | 5s polling with countdown indicator | Zero server changes needed. All APIs already exist. |
| Layout | Dashboard grid, all sections visible | Proxy/client counts are small (<50 typically); navigation overhead not worth it. |
| Style | Modern Clean | System font, purple/cyan/amber accents, #0f0f1a background, rounded cards, subtle borders. |

## API Endpoints (already exist, no changes)

| Endpoint | Method | Used for |
|----------|--------|----------|
| `/api/status` | GET | Header stats (version, uptime, counts) |
| `/api/proxies` | GET | Proxy table rows, traffic data |
| `/api/proxy/:name` | GET | Inline detail panel (config + sparkline) |
| `/api/proxy/:name/traffic` | GET | Per-proxy traffic sparkline data |
| `/api/clients` | GET | Client table rows |
| `/api/store/proxies` | GET/POST | Store list + create form |
| `/api/store/proxy/:name` | DELETE | Store delete button |

## Page Structure (top to bottom)

### 1. Header Bar
- Left: "frp-rs Dashboard" title, version
- Right: uptime, refresh countdown ("Refresh in 3s...")

### 2. Stat Cards Row
Four equally-wide cards:
- Clients online (purple accent, `#a78bfa`)
- Proxies active (cyan accent, `#60a5fa`)
- Traffic In (amber accent, `#f59e0b`)
- Traffic Out (rose accent, `#f472b6`)

Each card: large number + small uppercase label.

### 3. Traffic Chart
- Full-width card with `<canvas>` element
- Bar chart: bytes in (blue) and bytes out (orange) per 5s interval
- Rolling 10 data points (50s window)
- In-memory ring buffer, updated each poll

### 4. Proxy Table
- Columns: Name, Type, Status (dot + text), Port, Local Addr, In, Out, Conn, Expand
- Click ▶ on any row: inline detail panel expands below that row
- Sortable columns (optional, if <20 lines of JS)
- Online = green dot, Offline = red dot
- Traffic values formatted: B → KB → MB → GB

### 5. Proxy Detail Panel (inline expand)
- Expands below clicked row, pushes remaining rows down
- Left half: config table (type, remote port, local addr, encryption, compression, group, run_id)
- Right half: per-proxy traffic sparkline (small canvas, same rolling data)
- Connection count: active + total
- Click ▶ again or × to collapse

### 6. Client Table
- Columns: Run ID (truncated monospace), Address, Uptime, Proxies (comma-separated names)
- Proxy names color-coded by online/offline status

### 7. Store Section
- Left: create form (name, type, port, local_addr fields + Create button)
- Right: stored configs list with Delete buttons
- Client-side validation: name and type required
- Delete has confirmation prompt
- Success/error messages as inline toast/alert

## Visual Spec

### Colors
```
Background:       #0f0f1a
Card background:  #1a1a2e
Card border:      #2d2d4a
Text primary:     #e0e0e0
Text secondary:   #8b8baa
Text muted:       #6b7280
Accent purple:    #a78bfa  (clients)
Accent cyan:      #60a5fa  (proxies, traffic in)
Accent amber:     #f59e0b  (traffic out)
Accent rose:      #f472b6  (traffic out alt)
Green (online):   #34d399
Red (offline):    #f87171
```

### Typography
- Body: `system-ui, -apple-system, sans-serif`
- Data cells (numbers, addresses, run IDs): `ui-monospace, SF Mono, monospace`
- Header: 16px bold
- Stat numbers: 24px semibold
- Table headers: 10px uppercase, letter-spacing 0.5px
- Table rows: 12px

### Spacing
- Page padding: 16px
- Card padding: 14px
- Card gap: 12px
- Table cell padding: 6px 8px (header), 8px (data)
- Card border-radius: 6px

## JS Architecture

Single `<script>` block at end of HTML. Functions:

```
state = { proxies: [], clients: [], trafficHistory: [], expandedProxy: null }

load()           // fetch /api/status + /api/proxies, update DOM
loadClients()    // fetch /api/clients
renderStats(d)   // update header + stat cards
renderTraffic()  // draw canvas bar chart from trafficHistory
renderProxies()  // build proxy table rows, attach click handlers
expandProxy(n)   // fetch /api/proxy/:name + /api/proxy/:name/traffic, insert detail row
collapseProxy()  // remove detail row
renderClients()  // build client table rows
createProxy()    // POST /api/store/proxies with form data
deleteProxy(n)   // DELETE /api/store/proxy/:name with confirm

// Chart helpers
drawBarChart(canvas, data, colors)  // generic bar chart on canvas
formatBytes(b)                      // B/KB/MB/GB formatter (reuse existing)
formatDuration(s)                   // "2h 14m" formatter
```

## Files Changed

| File | Change |
|------|--------|
| `frp-server/src/dashboard.html` | Complete rewrite. ~500 lines HTML/CSS/JS. |

No Rust code changes. No `Cargo.toml` changes. All existing API endpoints used as-is.

## Testing

- Manual: start frps with dashboard enabled, open browser, verify all sections render
- Manual: verify 5s polling updates traffic data
- Manual: expand/collapse proxy detail
- Manual: create and delete stored proxy config via Store section
- Manual: resize browser — verify grid adapts (flexbox wrap)
- Existing `cargo test --workspace` must continue passing (no Rust changes)

## Out of Scope

- Real-time events (SSE/WebSocket) — 5s polling sufficient
- Authentication UI — server-side Basic Auth already handles this
- Mobile app / responsive redesign — desktop-first
- Dark/light mode toggle — dark only
- i18n — English only
- Chart export / CSV download
