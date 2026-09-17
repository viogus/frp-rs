# Refactor: Post-Review Cleanups

## Global Constraints

- `cargo build --workspace` zero warnings on all profiles (default, full, tiny, micro)
- `cargo test --workspace --all-features` pass
- `cargo clippy --workspace --all-targets --all-features -D warnings` zero warnings
- `cargo fmt --all -- --check` zero diffs
- No behavior changes — pure structural/local cleanup
- `unsafe` count must not increase
- Each commit compiles and passes tests independently

## Task 1: Arc micro-optimizations

**Target:** `frp-client/src/work_conn.rs`, `frp-client/src/service.rs`

Two micro-fixes:
1. work_conn.rs: per-packet `Arc<UdpSocket>` clone — avoid clone where reference suffices
2. service.rs: per-connection `ClientConfig` clone — pass `&Arc<RwLock<ClientConfig>>` instead of cloning the inner data

**Commit strategy:** One commit per fix. Each compiles + tests pass.

## Task 2: Fix minor nits from review

**Target:** `frp-client/src/vnet.rs`, `frp-client/src/lib.rs`, `frp-client/src/service.rs`, `frp-server/src/handlers.rs`

Three small fixes:
1. vnet.rs: remove redundant inner `#![cfg(feature = "vnet")]` (already cfg-gated in lib.rs `pub mod vnet`)
2. service.rs: replace `use crate::vnet::*;` glob import with explicit imports
3. handlers.rs: make `spawn_quic_drain` private (only called by `handle_quic_stream` in same module)

**Commit strategy:** One commit per fix.

## Task 3: handlers.rs split

**Target:** `frp-server/src/handlers.rs` (3036 lines)

Split into two modules:
- `handlers/mod.rs` — module root, re-exports
- `handlers/transport.rs` — accept-loop transport handlers: `handle_tls_connection` (both cfg variants), `handle_websocket_connection`, `handle_v2_connection`, `handle_v1_connection`, plus their helpers (`is_v2_magic`, `is_v1_type_byte`, `v2_handshake_and_read`), plus QUIC admission family (`QuicPreauthError`, `await_quic_preauth`, limiter constructors, `handle_quic_stream`, `spawn_quic_drain`, QUIC consts), plus `quic_admission_tests`
- `handlers/dispatch.rs` — visitor/work-conn dispatch handlers (existing content before Task 1 of the service split refactor added the transport handlers), plus `visitor_admission_tests`

**Constraints:**
- `handlers.rs` → `handlers/mod.rs` must preserve `pub mod handlers;` in lib.rs
- `pub(crate)` visibility on cross-module items
- Tests move with their functions
- Call sites in `service.rs` crate::handlers:: paths unchanged (they alias through mod.rs re-exports)

**Commit strategy:** One commit. Convert to directory module + split.

## Task 4: PreReadTransport / PreReadStream dedup

**Target:** `frp-core/src/transport/pre_read.rs`, `frp-core/src/transport/mod.rs`

Extract shared byte-replay logic. `PreReadTransport` (new in transport trait refactor) and `PreReadStream` (pre-existing, generic over `S`) have nearly identical `poll_read` with buffer replay + position tracking. Extract the common logic into a helper function or shared utility in the transport module.

**Constraint:** `PreReadStream` is generic over `S` and cannot implement `Transport` directly — the helper must work for both without changing either type's public API.

**Commit strategy:** One commit.

## Task 5: IoStream::Aead avoid re-box

**Target:** `frp-core/src/transport/mod.rs`

`IoStream::Aead` constructor does `Box::new(*inner)` — moves out of one box into another. Replace with `Self(inner)` which unsize-coerces `Box<AeadStream>` to `Box<dyn Transport>` with no re-allocation.

**Commit strategy:** One commit.
