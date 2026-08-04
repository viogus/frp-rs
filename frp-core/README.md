# frp-core

Shared foundation crate for the frp-rs reverse proxy. Provides wire protocol,
message types, transport abstraction, authentication, encryption, and utilities
used by both `frp-server` and `frp-client`.

## Modules

| Module | Purpose |
|--------|---------|
| `protocol` | V1/V2 frame read/write, length-prefixed JSON framing |
| `msg` | Wire message types (`FrpMessage` enum, 20+ variants) |
| `transport` | `IoStream` abstraction over TCP, TLS, KCP, QUIC, WebSocket, yamux, Cipher, Aead, SshChannel, PreRead, BufferedRead |
| `auth` | MD5(token+timestamp) auth + OIDC token verification |
| `config` | TOML config structs, Go→Rust compat normalization |
| `encryption` | PBKDF2-SHA1 key derivation, AES-128-CFB encrypt, Snappy compress |
| `cipher_stream` | Streaming AES-128-CFB `CipherReader`/`CipherWriter` |
| `bridge` | Encrypted/plain bidirectional data bridge with bandwidth limiting |
| `mux` | yamux-based TCP multiplexing (server + client) |
| `stun` | RFC 5389 STUN Binding Request/Response + XOR-MAPPED-ADDRESS |
| `crypto` | V2 AEAD primitives (AES-256-GCM, XChaCha20-Poly1305) |
| `v2_handshake` | V2 capability negotiation + key exchange |
| `kcp` | KCP reliable transport wrapper (`kcp/` directory: `protocol.rs` in-tree state machine + `mod.rs`, `session.rs`, `socket.rs`, `stream.rs`, `listener.rs`, `config.rs`) |
| `quic` | QUIC transport wrapper (quinn) |
| `bandwidth` | Token-bucket bandwidth limiter |
| `metrics` | `ProxyMetrics` counters + `ConnGuard` RAII tracking |
| `admin_auth` | HTTP Basic Auth middleware (axum) |
| `cli` | CLI argument parsing shared by frps/frpc binaries |

## Key Design Decisions

**Error type**: `frp_core::Error` is a `thiserror` enum covering Protocol,
Transport, Auth, Config, Io, and Serde. Used across all crates.

**Crypto**: `ring` for SHA256, AES-256-GCM, HKDF, HMAC. Go-compat ciphers
(AES-128-CFB, MD5, PBKDF2-SHA1) use dedicated crates (`aes`+`cfb-mode`,
`md-5`, `pbkdf2`+`sha1`). See [`encryption.rs`](src/encryption.rs) for
key derivation details.

**Encryption key**: Derived from auth token via `PBKDF2-SHA1(token, salt="frp",
iterations=64, keylen=16)`. Go frp v0.69.1 pre-built binary uses salt `"frp"`
(NOT `"crypto"` — the golib source says `"crypto"` but the binary was compiled
with `"frp"`).

**Transport**: `IoStream` unifies all stream types into a single enum.
`IoStream::into_split()` returns `std::io::Result<(ReadHalf, WriteHalf)>`
— static enum halves, not boxed trait objects — for the bridge layer.

**Feature flags**: `tls`, `kcp`, `quic`, `websocket`, `compression`, `chacha20`,
`oidc`, `vnet`, `tcp-mux`. All default ON. Disable to shrink binary size.

**TLS verification**: Uses `rustls-platform-verifier` for native OS trust store (macOS Security.framework, Windows Schannel, Linux openssl dir) instead of bundled `webpki-roots`. Saves ~300KB binary size.

## Usage

```rust
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;
use frp_core::msg::FrpMessage;
```

Add to `Cargo.toml`:
```toml
frp-core = { path = "../frp-core" }
```
