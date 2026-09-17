# Replace rust_tokio_kcp Vendored Dep with Direct kcp Crate Wrapper

**Issue:** [#113](https://github.com/viogus/frp-rs/issues/113)
**Date:** 2026-07-06
**Status:** design approved

## Motivation

`rust_tokio_kcp` v0.2.5 is unmaintained upstream — GitHub repo deleted/private, no updates. Currently vendored at `frp-core/vendored/rust_tokio_kcp/` (~5,900 lines, 231KB).

We only use a thin surface:
- `KcpStream` (AsyncRead/AsyncWrite)
- `KcpListener` (UDP socket + session management)
- `KcpConfig` / `KcpNoDelayConfig`
- `KcpStream::connect_with_conv()`
- FEC encode/decode via `reed_solomon_erasure`

**Dead weight:** `crypt.rs` (2,837 lines) — KCP-layer encryption unused (we use TLS + CipherStream). `reed-solomon-erasure`, `byteorder`, `crc32fast`, `spin` dependencies pulled in solely for vendored code.

## Scope

Replace ~5,900 lines vendored code with ~1,000 lines of direct `kcp` crate glue. Reuse existing `kcp_compat::Fec` (GF(2^8) Vandermonde-based, zero external deps) for FEC. Keep vendored `kcp-0.6.0` with Go compat patches.

## Architecture

New module layout under `frp-core/src/kcp/` (replaces single `kcp.rs`):

```
frp-core/src/kcp/
├── mod.rs      (~50)   Public API: re-exports, dial_kcp(), default_kcp_config()
├── socket.rs   (~200)  KcpSocket: owns UdpSocket, driver loop (tick/write_rx/udp_rx)
├── session.rs  (~250)  KcpSession: per-conv KCP+FEC, FEC header encode/decode, continuity detect
├── stream.rs   (~350)  KcpStream: AsyncRead/AsyncWrite, connects to session via mpsc
└── listener.rs (~200)  KcpListener: accept loop, FEC header detection, session routing
```

### Layered Design

| Layer | Lines | Responsibility |
|-------|-------|---------------|
| `KcpSocket` | ~200 | Owns `UdpSocket`, `tokio::select!` driver: tick timer + write channel + UDP recv. One per UDP socket. |
| `KcpSession` | ~250 | Per-conv session: KCP instance + `kcp_compat::Fec` codec + UDP send channel. FEC header encode/decode, continuity detection. |
| `KcpStream` | ~350 | `AsyncRead`/`AsyncWrite` impl. Read from KCP recv buffer, write to KCP send buffer + flush trigger. Public API surface. |
| `KcpListener` | ~200 | Accept loop: reads raw UDP, detects FEC headers, routes to correct session by conv ID. |

### Data Flow

**Send:** user `write()` → `KcpStream::poll_write` → mpsc tx → `KcpSocket` driver → `KcpSession::output()` → FEC encode → `UdpSocket::send()`

**Recv:** `UdpSocket::recv()` → `KcpSocket` driver → FEC header detect → route to `KcpSession` → FEC decode → `kcp.input()` → `kcp.recv()` → mpsc rx → `KcpStream::poll_read`

### Driver Loop

```rust
tokio::select! {
    _ = tick_interval.tick() => update all sessions, flush output
    Some((data, addr)) = write_rx.recv() => session.send(data), flush
    recv_result = udp_socket.recv_from(&mut buf) => route to session by conv
}
```

### KcpStream Internal Wiring

```rust
pub struct KcpStream {
    conv: u32,
    peer_addr: SocketAddr,
    write_tx: mpsc::UnboundedSender<(Vec<u8>, oneshot::Sender<io::Result<()>>)>,
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    read_buffer: Vec<u8>,
    read_pos: usize,
    shutdown: AtomicBool,
}
```

- **poll_write:** push data to `write_tx` → oneshot wait for flush confirm
- **poll_read:** drain `read_buffer` first. If empty, poll `read_rx`. KCP preserves datagram boundaries.
- **poll_flush:** send flush signal through `write_tx` → driver calls `kcp.flush()` → oneshot confirms
- **Shutdown:** set `shutdown` flag, send close signal to driver. Driver removes session, drops KCP instance.

Key constraints:
- Unbounded channels — KCP has built-in flow control (send window). If window full, `kcp.send()` returns `-1`, driver doesn't pull from channel.
- No `Arc<Mutex<>>` — `KcpStream` lives on user task, driver owns `Kcp` instance. All KCP mutations in driver loop only (single-threaded).
- `KcpStream` is `Send + Sync` but not `Clone` (one handle per connection).

## FEC Header Handling

Reuse `kcp_compat::Fec` (GF(2^8) Vandermonde Reed-Solomon, no external deps). New 6-byte header framing in `session.rs`:

```
FEC header (6 bytes): [seqid: u32 LE][flag: u16 LE]
  flag = 0xf1 (TYPE_DATA) or 0xf2 (TYPE_PARITY)
```

FEC header is at offset 0 in the UDP payload (no KCP-layer cipher — we use TLS + CipherStream instead). Current vendored code checks at offset 4 after nonce+CRC32 decryption; since we skip that layer, offset is 0.

When FEC is disabled (`data_shards == 0 && parity_shards == 0`), no FEC header is prepended — raw KCP data goes directly in UDP payload. This matches current vendored behavior and Go kcp-go wire format.

### Encode Path

1. Get raw KCP data from `kcp.output()`
2. If FEC enabled: split into `data_shards` blocks → `fec.encode()` → prepend 6-byte header per shard
3. If FEC disabled: send raw KCP data directly (no header)
4. Send each shard as separate UDP datagram

### Decode Path

1. Strip 6-byte header, extract `seqid` + `flag`
2. Track per-group shard sets: `HashMap<shard_id, ShardGroup>` where `shard_id = seqid / data_shards`
3. Continuity check: if time gap since last packet > RTO threshold, skip parity (non-continuous data)
4. When group has ≥ `data_shards` entries → `fec.decode()` → push to `kcp.input()`
5. Discard groups older than `MAX_SHARD_SETS` (3)

### Listener Detection

- Inspect raw UDP payload for FEC header by checking for known flag values (`0xf1`/`0xf2`) at expected offset (exact offset verified against Go kcp-go wire format during implementation; current vendored code checks at offset 4 post-decryption)
- If FEC detected: strip 6-byte header, extract KCP conv from payload
- If not: conv is at bytes [0..4], no FEC
- Route to correct session by conv ID + peer addr

## Config

Keep existing `KcpConfig` + `KcpNoDelayConfig` structs, moved into `mod.rs`. Remove unused fields:

```rust
pub struct KcpConfig {
    pub mtu: usize,           // default 1350
    pub nodelay: KcpNoDelayConfig,
    pub wnd_size: (u16, u16), // (sndwnd, rcvwnd)
    pub data_shards: usize,   // FEC, 0 = disabled
    pub parity_shards: usize, // FEC, 0 = disabled
    // REMOVED: crypt, listener_mode (unused)
}

pub struct KcpNoDelayConfig {
    pub nodelay: bool,        // default false (Go compat)
    pub interval: i32,        // default 40 (ms, Go compat)
    pub resend: i32,          // default 2 (fast retransmit)
    pub nc: bool,             // default true (no congestion, Go compat)
}
```

## What Gets Deleted

- `frp-core/vendored/rust_tokio_kcp/` — entire directory (~5,900 lines, 231KB)
- `reed-solomon-erasure` from `frp-core/Cargo.toml` (only used by vendored kcp)
- `byteorder` from `frp-core/Cargo.toml` (only used by vendored kcp)
- `crc32fast` from `Cargo.toml` — verify no other uses, likely dead
- `spin` from `Cargo.toml` — verify no other uses, likely dead

## What Stays

- `frp-core/vendored/kcp-0.6.0/` — patched KCP state machine (3 Go compat fixes: RTO linear backoff, flush ordering, early retransmit)
- `frp-core/src/kcp_compat.rs` — FEC/XOR codec (now imported by new `session.rs`)
- All `[patch.crates-io]` entries in workspace `Cargo.toml` for kcp-0.6.0

## Error Handling

- `KcpListener::bind()` → `io::Result<KcpListener>` (UDP bind failure)
- `KcpListener::accept()` → `io::Result<(KcpStream, SocketAddr)>` (session setup failure)
- `dial_kcp()` → `io::Result<KcpStream>` (UDP connect + session create)
- Driver errors (UDP send fail, KCP internal error) → log + drop session. Driver loop continues.
- Conv collision → return error from accept (existing session with same conv+addr)

## Testing

1. **Unit tests** in each module: FEC round-trip (reuse existing `kcp_compat` tests), FEC header encode/decode, continuity detection edge cases
2. **Integration test** `frp-core/tests/kcp.rs`: two `KcpSocket` instances, dial → send/recv round-trip, FEC loss simulation (drop every Nth shard)
3. **Existing compat tests** (`scripts/compat-test.sh`): KCP compat test cases against Go frp. Must pass: KCP+TLS, KCP+TLS+tcpMux, KCP+TLS+tcpMux+CipherStream. Same test matrix as PR #112.
4. **Binary size**: before/after `cargo build --release` comparison. Target: frps -50KB, frpc -50KB.

## Backward Compatibility

Zero API changes. `KcpStream`, `KcpListener`, `KcpConfig`, `KcpNoDelayConfig`, `dial_kcp()`, `default_kcp_config()` all keep same signatures. `IoStream::Kcp(KcpStream)` variant unchanged. `transport.rs` and service code require zero modifications.

## Non-Goals

- Changing KCP protocol behavior (keep vendored kcp-0.6.0 patches)
- Rewriting `kcp_compat.rs` (import and reuse, not absorb)
- Removing XOR cipher from `kcp_compat.rs` (unused but harmless, already tested)
- Performance optimization beyond parity with current implementation
