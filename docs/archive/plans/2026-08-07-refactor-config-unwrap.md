# Refactor: Config Split + Unwrap Elimination

## Global Constraints

- `cargo build` must pass with zero warnings on all profiles (default, full, tiny, micro)
- `cargo test --workspace --all-features` must pass
- `cargo clippy --workspace --all-targets --all-features -D warnings` zero warnings
- `cargo fmt --all -- --check` zero diffs
- Go frp v0.70.1 cross-compat must not break (`scripts/compat-test.sh`)
- All 53 external import sites of `frp_core::config::*` must keep working (no import path changes)
- No behavior changes — pure structural refactor
- `pub use` re-exports must preserve every public symbol's visibility
- Each commit must compile and pass tests independently
- `unsafe` count must not increase

## Task 1: Split config.rs into sub-modules

**Target:** `/home/claude/frp-rs/frp-core/src/config.rs` (5698 lines → directory of modules)

**Natural module boundaries:**

| Module | Contents | ~Lines |
|--------|----------|--------|
| `config/server.rs` | ServerConfig, SshTunnelGatewayConfig, AuthServerConfig, LogConfig, ObservabilityConfig, WebServerConfig, HttpPluginConfig, QuicOptions, ServerTransportConfig, PluginConfig, FeatureConfig, StoreConfig, PortsRange + their Default impls + default_* helpers | ~900 |
| `config/client.rs` | ClientConfig, AuthClientConfig, VirtualNetConfig, ProxyConfig, VisitorConfig, VisitorPluginConfig + their Default impls + default_* helpers | ~750 |
| `config/loader.rs` | load_server_config_from_str, load_client_config_from_str, ConfigPresence, validate_proxy_configs, validate_auth_token_source, validate_oidc_client_config, validate_server_config, validate_client_config, validate_no_duplicate_names, parse_bandwidth_limit, parse_allow_ports, count_ports | ~400 |
| `config/normalize.rs` | toml_to_json, flatten_to_table, load_config_from_file, normalize_server_config, normalize_client_config, normalize_web_server_section, normalize_proxies, normalize_visitors | ~800 |
| `config/file.rs` | load_server_config, load_client_config, process_includes, simple_glob, deep_merge_toml, collect_config_files | ~300 |
| `config/format.rs` | ConfigFormat, detect_format, parse_to_toml_value, json_to_toml, ini_to_toml, infer_ini_value | ~300 |
| `config/strict.rs` | known_set_from, known_server_keys, known_client_keys, run_strict_check, levenshtein, check_strict | ~250 |
| `config/tests.rs` | All 2287 lines of existing tests | ~2300 |

**`pub use` re-export strategy:**
`config/mod.rs` must re-export every public item:
```rust
mod server;    pub use server::*;
mod client;    pub use client::*;
mod loader;    pub use loader::*;
// etc.
```

**Commit strategy:** one commit per module. Each commit must compile + pass `cargo test -p frp-core`.

## Task 2: Eliminate production unwrap() calls

**Target:** 42 production unwraps across 3 crates

### A. CRITICAL — 5 data-plane `into_split().unwrap()` in client:

| File | Line | Context |
|------|------|---------|
| `frp-client/src/proxy.rs` | 377 | bridge_streams |
| `frp-client/src/visitor.rs` | 838 | XTCP P2P success |
| `frp-client/src/visitor.rs` | 951 | XTCP relay fallback |
| `frp-client/src/work_conn.rs` | 379 | Work connection handler |
| `frp-client/src/plugin/visitor.rs` | 317 | Plugin visitor bridge |

Fix: Extract `split_work_conn_halves` to `frp-core` as a public helper, or replicate the pattern. Must handle `PreRead`/`BufferedRead` Err case with `warn!` + return (no panic).

### B. Lock poisoning — 8 std Mutex unwraps:
Replace with `.lock().unwrap_or_else(|e| e.into_inner())`.

| File | Lines |
|------|-------|
| `frp-client/src/service.rs` | 709, 728, 734, 740, 3026, 3387 |
| `frp-server/src/ssh_gateway.rs` | 861 |
| `frp-client/src/admin.rs` | 536 |

### C. Provably unreachable — 22 sites:
Replace `.unwrap()` with `.expect("concise reason")`.

| File | Count | Key patterns |
|------|-------|---------|
| `frp-core/src/cipher_stream.rs` | 8 | Guarded by length/Some checks |
| `frp-core/src/config.rs` | 3 | strip_prefix filter, levenshtein guard |
| `frp-core/src/kcp/protocol.rs` | 2 | after `!is_empty()` check |
| `frp-core/src/xtcp_p2p.rs` | 2 | gated by `is_some()` |
| `frp-core/src/kcp/stream.rs` | 1 | Some set 2 lines above |
| `frp-core/src/kcp_compat.rs` | 1 | present shard index |
| `frp-client/src/visitor.rs` | 1 | `user_conn.take()` set Some earlier |
| `frp-client/src/service.rs` | 1 | guarded by `is_some_and` |
| `frp-server/src/ssh_gateway.rs` | 1 | fixed-size array |
| `frp-client/src/work_conn.rs` | 1 | after length check |
| `frp-client/src/plugin/visitor.rs` | 1 | constant literal parse |

### D. Config/init — 11 sites:
Replace with `.expect("message")`.

| File | Count |
|------|-------|
| `frp-core/src/quic.rs` | 1 |
| `frp-client/src/plugin/h2.rs` | 4 |
| `frp-client/src/plugin/socks5.rs` | 2 |

**Rules:**
- NEVER introduce new `unwrap()` — replaced with `expect()` with reason, `?`, or match
- Data-plane sites: no allocations in expect strings (no `format!`)
- For unreachable sites: expect string states WHY
- For into_split sites: MUST NOT panic — warn! + return
