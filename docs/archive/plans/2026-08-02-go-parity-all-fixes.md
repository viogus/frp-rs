# Go frp v0.70.1 Parity Gap Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the Go frp v0.70.1 parity gaps identified by the five read-only audits in `/tmp/frp-gap-{client,server,protocol,vnet-xtcp,security}.md`.

**Architecture:** Work directly in the existing Rust workspace, preserving the current crate/feature layout and Go wire semantics. Each task is scoped to a subsystem: client control/transport/plugin/admin, server vhost/plugin/ports/dashboard/SSH, XTCP, or VirtualNet. Changes must be tested with the existing unit/integration test patterns and `cargo test`.

**Tech Stack:** Rust workspace (`frp-core`, `frp-client`, `frp-server`, `frp-vnet`, `frpc`, `frps`), Tokio, tokio-rustls, yamux, quinn, kcp.

## Global Constraints

- Target: Go frp `v0.70.1` source at `/tmp/frp-src-0.70.1`; use it as the reference for wire/API semantics.
- Do not change V1/V2 framing, AEAD, KCP base parameters, token MD5, or known-aligned wire behavior unless a task explicitly requires it.
- Keep feature gates: code behind `tls`, `quic`, `kcp`, `websocket`, `dashboard`, `ssh`, `vnet` must still compile when the feature is disabled.
- Follow existing repository patterns: `frp_core::transport::DialOptions`, `frp_core::msg`, `serve_plugin`, `VhostManager`, `ProxyMetricsRegistry`, etc.
- New tests must assert real behavior, not mocks. Run the focused test before the full suite.
- Do not add new dependencies unless a task explicitly names one; prefer stdlib/Tokio/rustls/quinn capabilities already in `Cargo.toml`.
- Do not introduce non-ASCII into Rust source files unless the file already uses it; Chinese is allowed in plan/docs files.

---

### Task 1: Multi-tenant wire proxy names

**Files:**
- Modify: `frp-client/src/proxy.rs:63-100`
- Modify: `frp-client/src/control.rs:500-540`
- Modify: `frp-client/src/service.rs:700-900` (places that key `proxy_info_map`, health, and XTCP by proxy name)
- Test: `frp-client/tests/end_to_end.rs` or add unit tests near `create_new_proxy_msg`

**Interfaces:**
- Consumes: `frp_core::config::ClientConfig.user`, `frp_core::config::ProxyConfig.name`
- Produces: `create_new_proxy_msg(p: &ProxyConfig, local_addr: &str, user: &str) -> FrpMessage` (or an equivalent `wire_name` argument)

**Goal:** When `user` is non-empty, NewProxy must register `{user}.{proxy_name}` exactly like Go `naming.AddUserPrefix` (`/tmp/frp-src-0.70.1/pkg/naming/names.go:5-11`), and all client-side runtime maps/health/XTCP references must use the same wire name.

- [ ] **Step 1: Add failing tests**
  Add unit tests asserting `create_new_proxy_msg(..., "alice")` serializes `proxy_name == "alice.test"` for proxy name `"test"` and that empty user preserves `"test"`. Add or extend a runtime test asserting proxy status/work conn uses the prefixed name.
- [ ] **Step 2: Run tests to verify they fail**
  Run `cargo test -p frp-client proxy::tests --lib`; expected failure for the prefix assertion.
- [ ] **Step 3: Implement prefix**
  Change proxy registration and all name-keying paths to use `format!("{user}.{name}")` when `user` is non-empty. Keep visitor helper `create_visitor_conn_msg` unchanged.
- [ ] **Step 4: Run focused tests**
  Run `cargo test -p frp-client --lib proxy` and the end-to-end TCP test that exercises registration; expected pass.
- [ ] **Step 5: Commit**
  `git add` changed files and commit `fix(client): register proxies with user-prefixed wire names`.

---

### Task 2: Visitor standalone server connections use full transport config

**Files:**
- Modify: `frp-client/src/visitor.rs:249-256` and `frp-client/src/visitor.rs:831-838`
- Modify: `frp-client/src/service.rs:1060-1130` (construction of visitor runtime)
- Modify: `frp-client/src/plugin/visitor.rs:159-170` if it dials independently
- Test: `frp-client/tests/stcp_e2e.rs`, `frp-client/tests/xtcp_fallback.rs`

**Interfaces:**
- Consumes: `frp_core::config::ClientConfig` transport fields and `frp_core::transport::DialOptions`
- Produces: visitor dials through the same `DialOptions` as control/work conns, including `tcp_mux` wrapping via `wrap_client_mux`

**Goal:** STCP fallback, XTCP fallback, and virtual-net visitor server connections must honor `tcpMux`, `proxyURL`, `dnsServer`, `dialServerTimeout`, `dialServerKeepAlive`, `connectServerLocalIP`, TLS cert/key, and `disableCustomTLSFirstByte`.

- [ ] **Step 1: Write failing tests**
  Add a unit test that the STCP visitor dial path builds a yamux-wrapped `DialOptions` when `tcp_mux=true`; add a config/runtime test for `proxy_url` propagation into the visitor dial.
- [ ] **Step 2: Run to see failure**
  Run the focused STCP/XTCP fallback test; expected failure or assertion that options are defaulted.
- [ ] **Step 3: Implement**
  Pass a shared `DialOptions`/transport config into visitor tasks and call `wrap_client_mux` for `tcp_mux` before writing `NewVisitorConn`; include TLS cert/key.
- [ ] **Step 4: Run focused tests**
  `cargo test -p frp-client --test stcp_e2e` and `cargo test -p frp-client --test xtcp_fallback`; expected pass.
- [ ] **Step 5: Commit**
  `fix(client): apply transport options to visitor server connections`.

---

### Task 3: Correct `tls2raw` direction and cert/key

**Files:**
- Modify: `frp-client/src/plugin/tls2raw.rs:1-125`
- Modify: `frp-core/src/config.rs:881-918` if field aliases are needed for Go `crtPath/keyPath`
- Test: add `frp-client/tests/plugin_tls2raw.rs` or unit tests in `frp-client/src/plugin/tls2raw.rs`

**Interfaces:**
- Consumes: `PluginConfig.local_addr`, `PluginConfig.crt_file`, `PluginConfig.key_file`, `PluginConfig.proxy_protocol_version`
- Produces: plugin listens with a TLS acceptor inside frpc, terminates TLS from the tunnel side, and forwards plaintext to `local_addr`

**Goal:** Match Go `pkg/plugin/client/tls2raw.go:49-65`: tunnel side is TLS, local side is raw TCP. `crt_file`/`key_file` must be loaded and used; missing cert/key must fail at startup.

- [ ] **Step 1: Write failing tests**
  Create a test that starts a plaintext TCP echo backend, connects to the plugin with rustls as a client, and verifies plaintext bytes arrive at the backend. Assert missing cert/key returns startup error.
- [ ] **Step 2: Run to see failure**
  Run the new test; expected failure because current code connects to a TLS backend.
- [ ] **Step 3: Implement**
  Reverse the current plugin: build `TlsAcceptor` from `crt_file/key_file`, accept TLS on the tunnel side, and copy plaintext to `local_addr`. Keep PROXY header behavior compatible with the tunnel stream.
- [ ] **Step 4: Run focused tests**
  Run the new test and existing plugin compile/test suite; expected pass.
- [ ] **Step 5: Commit**
  `fix(plugin): implement tls2raw as tunnel-side TLS termination`.

---

### Task 4: OIDC client parity

**Files:**
- Modify: `frp-core/src/config.rs:947-1020` (`AuthClientConfig`)
- Modify: `frp-core/src/auth.rs:700-1000` (`OidcClient`)
- Modify: `frp-client/src/service.rs:261-325` (OIDC client construction)
- Test: `frp-server/tests/mock_oidc.rs`, `frp-server/tests/oidc_integration.rs`

**Interfaces:**
- Consumes: Go `pkg/config/v1/client.go:211-241`, `pkg/auth/oidc.go`
- Produces: `AuthClientConfig.oidc_token_source: Option<ValueSource>`, `additional_endpoint_params: HashMap<String,String>`, correct timestamp handling

**Goal:** Support `auth.oidc.tokenSource`, TOML map `additionalEndpointParams`, omit `audience` when empty, preserve timestamps across `set_login`/`set_ping`/`set_new_work_conn`, and validate required OIDC fields like Go.

- [ ] **Step 1: Write failing config/auth tests**
  Add tests parsing `additionalEndpointParams = { key = "value" }`, parsing `oidc.tokenSource`, and asserting empty audience omits the parameter from the token request.
- [ ] **Step 2: Run to see failure**
  Run `cargo test -p frp-core config::tests auth::tests`; expected failures.
- [ ] **Step 3: Implement**
  Change `additional_endpoint_params` to `HashMap<String, String>`, add `oidc_token_source`, wire token source into OIDC token acquisition, and stop clearing timestamps in OIDC `set_*`.
- [ ] **Step 4: Run focused tests**
  `cargo test -p frp-core --lib config auth` and `cargo test -p frp-server --test mock_oidc`; expected pass.
- [ ] **Step 5: Commit**
  `fix(auth): align OIDC client config and token-source semantics with Go`.

---

### Task 5: QUIC client options, hostname dialing, and mTLS certificate propagation

**Files:**
- Modify: `frp-core/src/quic.rs:280-340` (`dial_quic`, `dial_quic_with_params`)
- Modify: `frp-client/src/control.rs:229-239`
- Modify: `frp-client/src/work_conn.rs:267-316` and `frp-client/src/service.rs:982-1007`
- Test: `frp-core/tests/quic.rs`, `frp-client/tests/v2_quic_r2r.rs`

**Interfaces:**
- Consumes: `ClientConfig.quic_options`, `tls_cert_file`, `tls_key_file`, `tls_ca_file`, `tls_server_name`
- Produces: `dial_quic_with_params(addr, server_name, ca_file, cert_file, key_file, options)`; `WorkConnConfig` carries cert/key

**Goal:** Consume `[transport.quic]` max idle timeout, max incoming streams, and keepalive; resolve hostname server addresses for QUIC; pass client cert/key to control QUIC and non-yamux work connections.

- [ ] **Step 1: Write failing tests**
  Add a unit test parsing quic options into `dial_quic_with_params` and a hostname-resolution test with `127.0.0.1` mapping. Add a WorkConnConfig test asserting cert/key fields reach `DialOptions`.
- [ ] **Step 2: Run to see failure**
  Run focused quic tests; expected failure for params/hostname/cert.
- [ ] **Step 3: Implement**
  Use `tokio::net::lookup_host` or the existing `DialOptions` DNS path for QUIC hostnames, thread `QuicOptions` through `dial_quic`, and add cert/key to QUIC and work-conn dials.
- [ ] **Step 4: Run focused tests**
  `cargo test -p frp-core --lib quic` and `cargo test -p frp-client --test v2_quic_r2r` (with `quic` feature); expected pass.
- [ ] **Step 5: Commit**
  `fix(transport): consume QUIC options and propagate client certificates`.

---

### Task 6: WebSocket client pipelined frames and WS frame cap

**Files:**
- Modify: `frp-core/src/transport.rs:2818-2856` (`connect_ws_raw`)
- Modify: `frp-core/src/transport.rs:61-65` (frame cap)
- Test: `frp-core/tests/mux.rs` or add `frp-core/src/transport.rs` unit tests

**Interfaces:**
- Consumes: existing `WsByteStream` raw parser (`frp-core/src/transport.rs:120-400`)
- Produces: client `WsByteStream` consumes leftover bytes from the HTTP 101 read as WS frames instead of raw bytes

**Goal:** If Go frps sends the first WS frame in the same TCP segment as the 101 response, the client must parse the frame and not expose frame bytes as application bytes. Allow WS frames up to `V2_MAX_FRAME_PAYLOAD + AEAD overhead` (at least 64 KiB + 128 bytes).

- [ ] **Step 1: Write failing test**
  Add a test that feeds `HTTP/1.1 101\r\n...\r\n\r\n` plus a complete WS binary frame into the client raw stream and asserts the read returns the frame payload only.
- [ ] **Step 2: Run to see failure**
  Run the focused transport test; expected failure because leftover bytes are returned raw.
- [ ] **Step 3: Implement**
  Route leftover bytes through the raw WS frame parser (`feed_raw_bytes`) before exposing application bytes; raise the frame cap to account for V2 AEAD overhead.
- [ ] **Step 4: Run focused tests**
  `cargo test -p frp-core --lib transport` (with `websocket` feature); expected pass.
- [ ] **Step 5: Commit**
  `fix(transport): parse pipelined WebSocket frames after client upgrade`.

---

### Task 7: KCP+TLS client

**Files:**
- Modify: `frp-core/src/transport.rs:2190-2198`
- Modify: `frp-client/src/control.rs:32-80` if mux/feature gating changes
- Test: `frp-core/tests/kcp.rs`, `frp-client/tests/end_to_end.rs`

**Interfaces:**
- Consumes: `DialOptions.tls_enable`, `tls_cert_file`, `tls_key_file`, `tls_ca_file`, `tls_server_name`
- Produces: KCP transport wraps the KCP stream with TLS when `tls_enable` is true, matching the server accept path in `frp-server/src/service.rs:1006-1047`

**Goal:** Rust frpc with `protocol="kcp"` and TLS enabled must actually wrap KCP in TLS and advertise `tls=true` truthfully in V2 ClientHello.

- [ ] **Step 1: Write failing test**
  Add a KCP+TLS round-trip test (or enable the guarded one) using self-signed certs from `frp-client/tests/certs`.
- [ ] **Step 2: Run to see failure**
  Run focused KCP test; expected failure/plaintext mismatch.
- [ ] **Step 3: Implement**
  Build a TLS connector and wrap the KCP stream when `tls_enable` is true, preserving the frp TLS head byte behavior.
- [ ] **Step 4: Run focused tests**
  `cargo test -p frp-core --lib transport` and the KCP test; expected pass.
- [ ] **Step 5: Commit**
  `fix(transport): implement KCP+TLS client path`.

---

### Task 8: Client HTTP plugin headers, HTTP/2, and backend TLS policy

**Files:**
- Modify: `frp-client/src/plugin/http2http.rs`, `http2https.rs`, `https2http.rs`, `https2https.rs`
- Modify: `frp-client/src/plugin/mod.rs` if shared HTTP bridge plumbing is needed
- Test: add `frp-client/tests/plugin_http.rs`

**Interfaces:**
- Consumes: `PluginConfig.request_headers`, `PluginConfig.enable_http2`
- Produces: all four HTTP bridge plugins inject `requestHeaders` and honor `enableHTTP2`; `http2https`/`https2https` use `InsecureSkipVerify` for the backend like Go

**Goal:** Match Go `pkg/plugin/client/http_common.go:36-50`, `http2https.go:37`, and `https2https.go:37`.

- [ ] **Step 1: Write failing tests**
  Add tests that an HTTP bridge sends injected request headers and that backend TLS is accepted when self-signed.
- [ ] **Step 2: Run to see failure**
  Run the new plugin tests; expected missing-header/TLS failure.
- [ ] **Step 3: Implement**
  Thread request headers into the bridge request builders, set HTTP/2 listener config where applicable, and disable backend TLS verification for the Go-matching plugins.
- [ ] **Step 4: Run focused tests**
  `cargo test -p frp-client --test plugin_http`; expected pass.
- [ ] **Step 5: Commit**
  `fix(plugin): honor HTTP plugin request headers and backend TLS policy`.

---

### Task 9: UDP/data-plane client fixes

**Files:**
- Modify: `frp-client/src/work_conn.rs:447-521`, `1108-1182`
- Modify: `frp-core/src/proxy_protocol.rs:11-21`
- Test: `frp-client/tests/end_to_end.rs`, `frp-core/tests/proxy_protocol.rs` if present

**Interfaces:**
- Consumes: `ClientConfig.udp_packet_size`, `ProxyConfig.bandwidth_limit`, `ProxyConfig.proxy_protocol_version`
- Produces: UDP buffers sized by `udp_packet_size`, UDP work conns apply bandwidth limiting, UDP first packet gets PROXY v1/v2 header, PROXY v1 emits TCP6 for IPv6

**Goal:** Close the Important client data-plane gaps from `/tmp/frp-gap-client.md` items 9, 13 and `/tmp/frp-gap-protocol.md` M4/M7.

- [ ] **Step 1: Write failing tests**
  Add tests for `udp_packet_size` buffer selection, UDP PROXY header emission, and PROXY TCP6 formatting.
- [ ] **Step 2: Run to see failure**
  Run focused work_conn/proxy_protocol tests; expected failures.
- [ ] **Step 3: Implement**
  Replace fixed 65535 buffer, add UDP bandwidth limiter, add PROXY header before first UDP packet, and choose `TCP6` when either address is IPv6.
- [ ] **Step 4: Run focused tests**
  `cargo test -p frp-client --lib work_conn` and `cargo test -p frp-core --lib proxy_protocol`; expected pass.
- [ ] **Step 5: Commit**
  `fix(dataplane): UDP packet size, PROXY header, and bandwidth limiting`.

---

### Task 10: Client proxy URL, DNS scope, reload, admin/store, and config redaction

**Files:**
- Modify: `frp-core/src/transport.rs:1917-1927,2128-2151` (proxy auth/socks5h)
- Modify: `frp-client/src/proxy.rs:130-140` (local DNS)
- Modify: `frp-client/src/service.rs:2354-2365` and `frp-client/src/reload.rs` (visitor reload)
- Modify: `frp-client/src/admin.rs:354-383,498-534,606-640`
- Modify: `frp-client/src/store.rs:39-43,264-324`
- Test: `frp-client/tests/reload_integration.rs`, `frp-client/tests/api_tests.rs`, config unit tests

**Interfaces:**
- Consumes: `ClientConfig.dns_server`, `proxy_url`, `store`, `web_server`
- Produces: visitor reload, Go-style `GET /api/reload`, `GET /api/proxy|visitor/{name}/config`, `source` field, secret_key redaction, strict known keys

**Goal:** Close client management/admin gaps and make `dnsServer` apply to local backends; proxy URL supports userinfo auth and socks5h remote DNS.

- [ ] **Step 1: Write failing tests**
  Add admin tests for GET reload/config endpoints, store JSON shape, and redaction of `secret_key`; add transport test for HTTP proxy auth and socks5h.
- [ ] **Step 2: Run to see failure**
  Run focused tests; expected failures.
- [ ] **Step 3: Implement**
  Implement visitor diff/reload, add admin endpoints and Go-compatible store serialization, add missing sensitive keys, add proxy auth/socks5h handling, and apply DNS resolver to local connections.
- [ ] **Step 4: Run focused tests**
  `cargo test -p frp-client --test api_tests --test reload_integration` and `cargo test -p frp-core --lib transport`; expected pass.
- [ ] **Step 5: Commit**
  `fix(client): align reload, store/admin API, proxy auth, and DNS scope`.

---

### Task 11: Server port accounting and allowPorts/reservation

**Files:**
- Modify: `frp-server/src/control/proxy_ops.rs:367-429,513-520,843-890`
- Modify: `frp-core/src/config.rs:265-290,1971-1985`
- Modify: `frp-server/src/proxy.rs:488-543`
- Modify: `frp-server/src/service.rs:339-348`
- Test: `frp-server/src/proxy.rs` unit tests, `frp-core/src/config.rs` unit tests

**Interfaces:**
- Consumes: `ServerConfig.allow_ports`, `max_ports_per_client`
- Produces: `acquire_port`/`release_port` semantics matching Go: only TCP/UDP consume ports; HTTP/HTTPS/TCPMux/STCP/XTCP do not; 24h reservation for zero-remote-port names

**Goal:** HTTP/HTTPS/TCPMux/STCP/XTCP must not consume `allowPorts` or `maxPortsPerClient`; `{single=N}` parses correctly; invalid allow-ports entries fail config validation instead of silently disabling restrictions; release retains port by proxy name for 24h.

- [ ] **Step 1: Write failing tests**
  Add config tests for `single` and invalid ranges; add server tests that registering STCP/HTTP does not increment used ports and that a released zero-port TCP name is reused within 24h.
- [ ] **Step 2: Run to see failure**
  Run focused config/proxy_ops tests; expected failures.
- [ ] **Step 3: Implement**
  Fix allow-ports parser/normalizer, skip port acquisition for non-TCP/UDP proxies, adjust max-port counting, and add reservation map with expiry.
- [ ] **Step 4: Run focused tests**
  `cargo test -p frp-core --lib config` and `cargo test -p frp-server --lib proxy proxy_ops`; expected pass.
- [ ] **Step 5: Commit**
  `fix(server): align port accounting, allowPorts, and 24h reservation`.

---

### Task 12: vhost HTTPS SNI passthrough

**Files:**
- Modify: `frp-server/src/vhost.rs:617-666`
- Modify: `frp-server/src/control/proxy_ops.rs:612-680` (HTTPS proxy registration)
- Test: `frp-server/tests/v2_integration.rs` or add `frp-server/tests/vhost_https_sni.rs`

**Interfaces:**
- Consumes: existing `VhostManager` SNI routing
- Produces: `run_vhost_https_listener` reads only ClientHello SNI, returns the original encrypted stream, and bridges it to the matching frpc HTTPS proxy

**Goal:** frps must not terminate TLS for HTTPS vhosts; it must forward the encrypted TLS bytes after SNI routing, matching Go `pkg/util/vhost/https.go:39-50`.

- [ ] **Step 1: Write failing test**
  Add a test that connects with TLS ClientHello SNI `example.com`, verifies the stream is not decrypted, and asserts the backend receives TLS bytes.
- [ ] **Step 2: Run to see failure**
  Run focused test; expected current code performs a full TLS handshake.
- [ ] **Step 3: Implement**
  Use a peek/parse of ClientHello to extract SNI, route by SNI, and hand the original `IoStream`/TcpStream to the bridge without wrapping in `TlsStream`.
- [ ] **Step 4: Run focused tests**
  Run the new SNI test and existing HTTPS vhost tests; expected pass.
- [ ] **Step 5: Commit**
  `fix(vhost): pass HTTPS vhost TLS bytes through by SNI`.

---

### Task 13: HTTP server plugin protocol and fail-closed behavior

**Files:**
- Modify: `frp-server/src/plugin/http.rs:1-130`
- Modify: `frp-server/src/control/login.rs:405`, `proxy_ops.rs:263`, `handlers.rs:1003`, `proxy.rs:181,284`, `control/pool.rs:308,365`
- Test: add `frp-server/tests/http_plugin.rs` or extend existing integration

**Interfaces:**
- Consumes: `HttpPluginConfig.url`, `ops`, `timeout`, `tls_verify`, `enable_control`
- Produces: Go-style HTTP plugin calls with uppercase op, `version=0.1.0`, `op` query, `X-Frp-Reqid`, HTTP 200 requirement, `reject`/`unchange`/`content` mutation, and fail-closed on transport/status errors

**Goal:** Match Go `pkg/plugin/server/http.go:40-98` and `manager.go:90-105`; plugin errors must reject the operation instead of allowing it.

- [ ] **Step 1: Write failing tests**
  Add a mock plugin asserting request URL/query/header and rejecting login; add a test where the plugin is unreachable and login must fail.
- [ ] **Step 2: Run to see failure**
  Run focused server tests; expected current fail-open and wrong wire format.
- [ ] **Step 3: Implement**
  Rewrite `HttpPluginManager::notify` to send `?version=0.1.0&op=Login`, `X-Frp-Reqid`, validate HTTP 200, apply content mutations, honor `tls_verify`, and return error on any plugin failure.
- [ ] **Step 4: Run focused tests**
  Run new plugin tests and existing login/new_proxy tests; expected pass.
- [ ] **Step 5: Commit**
  `fix(plugin): implement Go HTTP server plugin contract and fail closed`.

---

### Task 14: TCPMux passthrough

**Files:**
- Modify: `frp-server/src/tcpmux.rs:218-225`
- Test: `frp-server/tests/tcpmux.rs`

**Interfaces:**
- Consumes: `ServerConfig.tcp_mux_passthrough`, `state.tcp_mux_passthrough`
- Produces: when enabled, preserve the full CONNECT request bytes and do not send the HTTP 200 response

**Goal:** Match Go `pkg/util/tcpmux/httpconnect.go:73-82,122-125`.

- [ ] **Step 1: Write failing test**
  Extend tcpmux integration to assert passthrough mode does not return 200 and backend sees `CONNECT`.
- [ ] **Step 2: Run to see failure**
  Expected current test fails because 200 is always sent.
- [ ] **Step 3: Implement**
  Gate the 200 write on `!passthrough` and forward the complete request bytes to the backend.
- [ ] **Step 4: Run focused tests**
  `cargo test -p frp-server --test tcpmux`; expected pass.
- [ ] **Step 5: Commit**
  `fix(tcpmux): implement tcpMuxPassthrough`.

---

### Task 15: vhost HTTP reverse-proxy behavior, groups, and bind semantics

**Files:**
- Modify: `frp-server/src/vhost.rs:442-600`
- Modify: `frp-server/src/control/proxy_ops.rs:540-610,681-714`
- Modify: `frp-server/src/service.rs:573,812-865`
- Test: `frp-server/tests/dashboard_integration.rs`, `frp-server/tests/tcpmux.rs`, new vhost HTTP tests

**Interfaces:**
- Consumes: `ProxyInfo` request headers/response headers/group fields, `ServerConfig.proxy_bind_addr`, bind/vhost ports
- Produces: X-Forwarded-For, requestHeaders, Proxy-Authorization/absolute URI handling, h2c, 504 timeout, HTTP/HTTPS/TCPMux groups, TCPMux routeByHTTPUser/subdomain, port reuse with bindPort, proxyBindAddr binding

**Goal:** Close Important vhost gaps from `/tmp/frp-gap-server.md` I1-I3.

- [ ] **Step 1: Write failing tests**
  Add vhost HTTP tests for X-Forwarded-For/requestHeaders/504; group round-robin; TCPMux routeByHTTPUser; port reuse and proxyBindAddr.
- [ ] **Step 2: Run to see failure**
  Run focused vhost/tcpmux tests; expected failures.
- [ ] **Step 3: Implement**
  Upgrade the raw forwarding path to Go-style reverse proxy semantics, add group routing in VhostManager/TcpMux routes, and bind vhost/TCPMux listeners on proxyBindAddr with reuse of bindPort.
- [ ] **Step 4: Run focused tests**
  Run new vhost/tcpmux tests and existing HTTP/HTTPS tests; expected pass.
- [ ] **Step 5: Commit**
  `fix(vhost): implement Go HTTP reverse-proxy and group semantics`.

---

### Task 16: SSH gateway standard `ssh -R` workflow

**Files:**
- Modify: `frp-server/src/ssh_gateway.rs:1-900`
- Test: `frp-server/tests/ssh_gateway.rs`

**Interfaces:**
- Consumes: `sshTunnelGateway` config, russh channel APIs
- Produces: support `tcpip-forward`/`forwarded-tcpip` reverse channels and NoClientAuth when authorized keys file is empty

**Goal:** Match Go `pkg/ssh/server.go:98-141,355-371` and `gateway.go:74` so `ssh -R :port:host:port v0@frps` works.

- [ ] **Step 1: Write failing test**
  Add an SSH integration test using russh client that requests `tcpip-forward` and sends data through the reverse channel.
- [ ] **Step 2: Run to see failure**
  Expected current code rejects tcpip-forward.
- [ ] **Step 3: Implement**
  Accept tcpip-forward requests, parse the gateway proxy flags, open `forwarded-tcpip` channels, and bridge to work conns; allow NoClientAuth when no authorized keys file is configured.
- [ ] **Step 4: Run focused tests**
  `cargo test -p frp-server --test ssh_gateway`; expected pass.
- [ ] **Step 5: Commit**
  `feat(ssh): implement Go-compatible ssh -R reverse gateway`.

---

### Task 17: Dashboard v1/v2 API contracts, offline clients, pprof/assets, and management security

**Files:**
- Modify: `frp-server/src/dashboard.rs`
- Modify: `frp-server/src/dashboard_v2.rs`
- Modify: `frp-server/src/state.rs`
- Modify: `frp-server/src/store.rs`
- Modify: `frp-client/src/admin.rs`
- Modify: `frp-core/src/config.rs`
- Test: `frp-server/tests/dashboard_integration.rs`, `frp-server/tests/dashboard_v2_integration.rs`, `frp-client/tests/api_tests.rs`

**Interfaces:**
- Consumes: `ClientRegistry`, `ProxyMetricsRegistry`, `ServerConfig.web_server`, `ClientConfig.web_server`
- Produces: Go-shaped v1/v2 responses, offline client records, prune semantics, pprof/static assets, auth on `/`, `secret_key` redaction, 0600 store files, file tokenSource not requiring unsafe, auth validation

**Goal:** Close `/tmp/frp-gap-server.md` I4-I6, I9 and `/tmp/frp-gap-security.md` I1-I5.

- [ ] **Step 1: Write failing tests**
  Add tests for v1/v2 JSON fields, offline clients, prune behavior, dashboard root auth, store permissions, secret_key redaction, and auth validation.
- [ ] **Step 2: Run to see failure**
  Run focused dashboard/admin/config tests; expected failures.
- [ ] **Step 3: Implement**
  Align response models and query filters, persist client registry entries, retain offline metrics, implement pprof/assets routes, secure `/`, redact `secret_key`, set 0600 on store writes, remove `file://` from unsafe allowlist, and validate auth method/scopes.
- [ ] **Step 4: Run focused tests**
  Run dashboard/admin/config tests; expected pass.
- [ ] **Step 5: Commit**
  `fix(management): align dashboard/admin API contracts and security defaults`.

---

### Task 18: XTCP parity

**Files:**
- Modify: `frp-core/src/xtcp_p2p.rs:1-900`
- Modify: `frp-client/src/visitor.rs:342-590`
- Modify: `frp-client/src/service.rs:1527-1567,2044,2141-2151`
- Modify: `frp-core/src/config.rs:1433-1437,1545-1547`
- Test: `frp-core/tests/xtcp_p2p.rs`, `frp-client/tests/xtcp_hole_punch.rs`, `xtcp_edge.rs`, `xtcp_fallback.rs`

**Interfaces:**
- Consumes: `NatHoleResp`, `NatHoleSid`, `NatTraversal` fields, `QuicConnection`
- Produces: Go-compatible `MakeHole` state machine (TTL, random listen/scan ports, send delay, multi-socket), assisted-address probing, QUIC data plane, keepTunnelOpen worker, secret-key magic parity

**Goal:** Close `/tmp/frp-gap-vnet-xtcp.md` XTCP P0-P3.

- [ ] **Step 1: Write failing tests**
  Add unit tests for MakeHole candidate generation/TTL and assisted-address probes; add keepTunnelOpen retry/rate tests; add QUIC P2P test gated by `quic` feature.
- [ ] **Step 2: Run to see failure**
  Run focused XTCP tests; expected failures.
- [ ] **Step 3: Implement**
  Port the Go `MakeHole` state machine into `frp_core::xtcp_p2p`, probe assisted addresses, select KCP/QUIC data plane from negotiated protocol, add keep-open worker with rate limiter, and use `NatHoleSid` magic consistently.
- [ ] **Step 4: Run focused tests**
  Run XTCP unit/integration tests; expected pass (network-gated tests may be skipped without public NAT).
- [ ] **Step 5: Commit**
  `feat(xtcp): implement Go MakeHole, assisted probing, and QUIC data plane`.

---

### Task 19: VirtualNet isolation, routing, reload, and control plane

**Files:**
- Modify: `frp-vnet/src/router.rs`, `controller.rs`, `tun.rs`
- Modify: `frp-client/src/service.rs`, `frp-client/src/visitor.rs`, `frp-client/src/reload.rs`
- Modify: `frp-server/src/control/nathole.rs`, `frp-server/src/control/proxy.rs`
- Modify: `frp-core/src/msg.rs` if control-plane framing changes are required
- Test: `frp-client/tests/end_to_end.rs`, `frp-core/tests/mux.rs`, new vnet tests

**Interfaces:**
- Consumes: `VirtualNetConfig`, `ProxyConfig.virtual_net`, `VnetRouteAdvertise`, `VnetRouteRemove`
- Produces: namespace-aware routing, Go-compatible VnetPacket framing/encryption, IPv6 TUN, single-controller semantics, OS routes, reload cleanup, exponential backoff

**Goal:** Close `/tmp/frp-gap-vnet-xtcp.md` VirtualNet P1-P3 and make isolation actually enforced.

- [ ] **Step 1: Write failing tests**
  Add route isolation tests, IPv6 TUN config tests, reload/route-removal tests, and backoff tests.
- [ ] **Step 2: Run to see failure**
  Run focused vnet tests; expected failures.
- [ ] **Step 3: Implement**
  Add vnet namespace to routes/forwarding, route control packets through standard framing/compression/encryption, support IPv6 TUN where the OS permits, consolidate per-client controller/TUN, add OS routes, broadcast removals, and apply exponential backoff.
- [ ] **Step 4: Run focused tests**
  Run vnet unit/integration tests; expected pass where TUN privileges are available.
- [ ] **Step 5: Commit**
  `fix(vnet): enforce isolation and align routing/reload semantics`.

---

### Task 20: Documentation and README parity claims

**Files:**
- Modify: `README.md:60-110,300-380`
- Modify: `docs/go-frp-compat-audit.md`
- Modify: `TODO.md:108`

**Interfaces:**
- Consumes: the final audit state and all task outcomes
- Produces: README/compat docs state implemented parity, remaining known limitations, feature-gate notes, and version distinction (`frp-rs 0.7.1` vs Go `v0.70.1`)

**Goal:** Remove unsupported “100% parity / full XTCP” claims and accurately list current compatibility.

- [ ] **Step 1: Audit current docs**
  Compare claims with the final code state.
- [ ] **Step 2: Update docs**
  Replace absolute parity claims with a factual matrix; list known gaps and build-feature requirements.
- [ ] **Step 3: Verify**
  `rtk git diff --stat` and manual read; no code changes.
- [ ] **Step 4: Commit**
  `docs: correct Go frp parity claims and known limitations`.

