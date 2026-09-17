# V2+QUIC Handshake — Design Spec

**Date**: 2026-06-29
**Status**: design-approved
**Target**: Full V2 protocol support over QUIC transport (Rust↔Rust primary, Go↔Rust compat)

## Context

QUIC transport (`quic` feature) dials/accepts V1-only. V2 handshake (ClientHello/ServerHello, AEAD crypto negotiation) works on TCP/WS/KCP but is explicitly skipped for QUIC (`control.rs:147`: "TODO: V2 handshake over QUIC when V2+QUIC interop needed.").

Go frp v0.69.1 treats each QUIC stream independently — V2 magic + protocol framing on every stream. The frp-rs QUIC layer already supports multi-stream (`QuicConnection::open_bi()`/`accept_bi()`), matching Go frp's quic-go behavior. All building blocks needed (V2 handshake, AEAD stream, V2 frame I/O) already exist and operate on `IoStream` — they just aren't wired into the QUIC accept/dial paths.

## Architecture

```
Client (dial)                          Server (accept)
─────────────                          ────────────────
dial_quic() → (stream0, quic_conn)
  │
  ├─ write_v2_magic(stream0)
  ├─ v2_handshake_client(stream0)      detect_v2_magic(stream0)
  │   ├─ ClientHello(frame_type=1) ──→   ├─ ClientHello → ServerHello
  │   └─ ←── ServerHello(frame_type=2)   └─ crypto_ctx
  ├─ write_v2_frame(Login) ──────────→ read_v2_frame() → Login
  ├─ ←── write_v2_frame(LoginResp)       write_v2_frame(LoginResp)
  ├─ AeadStream::new(stream0)            AeadStream::new(stream0)
  └─ V2 message loop (AEAD-encrypted)   handle_control(v2=true, crypto_ctx)
       │
       ├─ quic_conn.open_bi() → stream1
       │   write_v2_magic(stream1) ───→ detect_v2_magic(stream1)
       │   write_v2_frame(NewWorkConn)   handle_work_conn_inner(stream1, v2=true)
       │
       └─ quic_conn.open_bi() → stream2
           write_v2_magic(stream2) ───→ ...same...
```

**Key design decisions:**

- **V2 magic on every QUIC stream** — matches Go frp: `wire.WriteMagicIfV2()` per stream
- **Per-stream independence** — each stream has its own V2 handshake or message dispatch; QUIC is pure transport
- **No yamux on QUIC** — QUIC provides native stream multiplexing; tcpMux already gated to `TransportProtocol::Tcp`
- **AEAD only on control stream** — work connection streams use plain V2 framing (matching Go frp + existing TCP work conn behavior)
- **Backward compat** — `v2=false` → unchanged V1 QUIC path; zero regression risk

## Implementation Plan

### Phase 1: Client QUIC dial (`frp-client/src/control.rs`)

**Current** (lines 136-148): QUIC branch returns `(IoStream::Quic(stream), None, Some(qc))` — skips all V2/yamux logic below and falls through directly to Login send.

**Change**: When `self.v2 && TransportProtocol::Quic`:
1. `dial_quic()` → `(stream, quic_conn)` (unchanged)
2. `protocol::write_v2_magic(&mut stream)` — write V2 magic on first stream
3. `v2_handshake_client(&mut stream, "quic", self.tls_enable, false, true)` — ClientHello/ServerHello, no tcpMux, with crypto
4. Return `(IoStream::Quic(stream), None, Some(quic_conn), crypto_ctx)`

`v2_handshake_client` already takes `&mut IoStream` — `IoStream::Quic` variant works through `write_raw_v2_frame`/`read_raw_v2_frame`.

When `!self.v2`: existing V1 behavior unchanged.

### Phase 2: Server QUIC accept (`frp-server/src/service.rs`)

**Current** (lines 375-450): Accepts QUIC stream → `read_msg_v1()` → if Login → `handle_control(..., false, None)`. Drain task also reads V1.

**Change**: Accept loop:
1. Accept first QUIC stream (unchanged)
2. `detect_v2_magic(&mut ctl).await?` — read 7 bytes
3. If V2 magic matched:
   - `v2_handshake_server(&mut ctl).await?` → `(None, Some(crypto_ctx))`
   - `ctl.read_v2_frame().await?` → Login (plaintext V2 message)
   - `handle_control(ctl, login, state, None, None, true, crypto_ctx).await`
4. If NOT V2 magic:
   - Wrap consumed bytes: `IoStream::BufferedRead(magic_buf, 0, Box::new(IoStream::Quic(stream)))`
   - Fall through to existing `read_msg_v1()` path (backward compat)

Drain task (lines 391-428):
1. `drain_conn.accept_bi()` → new stream (unchanged)
2. `detect_v2_magic(&mut wc)` → if V2: read first V2 message + dispatch via existing `dispatch_v2_message` path
3. If not V2: wrap consumed bytes + existing V1 `read_msg_v1()` path

### Phase 3: Client work conn over QUIC (`frp-client/src/work_conn.rs`)

**Already partially implemented** (lines 182-193, 305-310):
- QUIC work conns open via `quic_conn.open_bi()` ✓
- V2 magic written before NewWorkConn ✓

**No changes needed** for work conn creation. The existing code handles V2 magic + V2 framing on QUIC work streams.

### Phase 4: Handle V2+QUIC in `handle_control` server-side

`handle_control` (control.rs:68) already accepts `v2: bool` and `crypto_ctx: Option<CryptoContext>`. When both are set:
1. LoginResp is written as plaintext V2 frame ✓
2. After LoginResp, stream is wrapped in `IoStream::Aead(Box::new(aead))` ✓
3. Subsequent messages use AEAD-encrypted V2 framing ✓

**No changes needed** — the control handler already supports V2+AEAD for TCP/WS/KCP paths.

## Error Handling

| Scenario | Behavior |
|----------|----------|
| `detect_v2_magic` returns non-V2 bytes | Bytes replayed via `BufferedRead`; falls through to V1 path |
| ClientHello never arrives (timeout) | 10s timeout → `Error::Protocol("V2 handshake timeout")` → drop connection |
| Algorithm mismatch (no overlap) | Server sends `ServerHello::with_error("unsupported codec")` → drop |
| AEAD key derivation fails | `Error::Protocol` → drop, never silent plaintext fallback |
| QUIC connection closed during drain | `accept_bi()` error → drain exits cleanly; `CancellationToken` cancels on control exit |
| `v2=false` in config | All QUIC paths unchanged (V1-only, zero regression) |
| Work conn stream: magic detected but first msg is not NewWorkConn | Warn + drop stream; matches existing V1 behavior for unexpected messages |

## Testing

### Unit / integration

- `v2_quic_r2r` — Rust↔Rust V2+QUIC compat test (new)
  - Client: `v2=true`, `quic` transport
  - Server: QUIC listener with V2 detection
  - Verify: TCP proxy tunnel over V2 QUIC control + work conn

### Guarded compat tests

- `v2_quic_g2r` — Go frpc → Rust frps over QUIC V2 (behind `GO_FRP_V2=1`)
- `v2_quic_r2g` — Rust frpc → Go frps over QUIC V2 (behind `GO_FRP_V2=1`)

### Regression

- All existing QUIC compat tests (V1) must remain green
- All existing V2 compat tests (TCP/WS/KCP) must remain green
- `cargo build --workspace` with `quic` feature enabled/disabled
- `cargo clippy --workspace` — 0 warnings

## Modified Files

| File | Lines changed | Description |
|------|---------------|-------------|
| `frp-client/src/control.rs` | ~30 | QUIC branch: V2 handshake + AEAD wrap |
| `frp-server/src/service.rs` | ~60 | QUIC accept: V2 detect + handshake + AEAD; drain: V2 detect |

No new files. No new dependencies. All building blocks exist in `frp-core`.
