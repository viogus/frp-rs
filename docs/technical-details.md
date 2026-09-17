# frp-rs Technical Details — moved

This document has been merged into [**frp-rs Architecture**](architecture.md),
which is now the single canonical description of how frp-rs works.

It previously duplicated the same subsystems across three files
(`technical-details.md`, `architecture.md`, and §2 of `developing.md`), so the
content was consolidated:

| What you were looking for | Now at |
|---|---|
| Overview, crate layout, dependency graph | [architecture.md § Overview](architecture.md#overview) |
| Project structure / module tree | [architecture.md § Project Structure](architecture.md#project-structure) |
| V1 frame format, message types, V2 | [architecture.md § Wire Protocol](architecture.md#wire-protocol) |
| Work connection lifecycle, pooling, bridging | [architecture.md § Work Connection Lifecycle](architecture.md#work-connection-lifecycle) |
| Server accept loop, `InternalMsg`, `select!` loop | [architecture.md § Server Connection Lifecycle](architecture.md#server-connection-lifecycle) and [§ Server Control Plane](architecture.md#server-control-plane-the-internalmsg-channel) |
| Authentication | [architecture.md § Authentication](architecture.md#authentication) |
| Encryption, key derivation, compression | [architecture.md § Encryption](architecture.md#encryption) |
| Transport abstraction and status | [architecture.md § Transport Abstraction](architecture.md#transport-abstraction) |
| XTCP NAT hole punching | [architecture.md § XTCP NAT Hole Punching](architecture.md#xtcp-nat-hole-punching) |
| Config normalization | [architecture.md § Config Normalization](architecture.md#config-normalization) |

Other entry points:

- [Documentation index](README.md) — all docs
- [Developer Guide](developing.md) — adding proxy types, building, debugging, testing, releasing
- [CLAUDE.md](../CLAUDE.md) — contributor/agent rules and invariants

This stub is kept so existing links and bookmarks to `technical-details.md`
continue to work.
