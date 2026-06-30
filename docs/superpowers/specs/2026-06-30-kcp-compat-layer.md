# KCP Compatibility Layer: Go kcp-go vs Rust kcp

**Date:** 2026-06-30
**Status:** Design / Implementation

## 1. Go kcp-go Architecture

Go's [kcp-go](https://github.com/xtaci/kcp-go) is a session-oriented reliable transport built on top of raw KCP. It adds two layers between application data and the wire:

### 1.1 XOR Encryption Layer (innermost)

A simple repeating-key XOR cipher:

```
for i := range data {
    data[i] ^= key[i % len(key)]
}
```

- Applied **before FEC encoding** on send, **after FEC decoding** on receive.
- Key is derived from the connection's encryption configuration.
- When key is empty, XOR is a no-op.

### 1.2 FEC (Forward Error Correction) Layer

Uses Reed-Solomon codes over GF(2^8) with irreducible polynomial `x^8 + x^4 + x^3 + x^2 + 1` (0x11D).

**Encoding** (send path):
```
1. Split payload into `data_shards` equal-sized blocks (zero-pad trailing block if needed)
2. Apply XOR to each shard (if enabled)
3. Compute `parity_shards` using Vandermonde matrix:
   matrix[i][j] = (i+1)^j   for parity row i, data column j
4. Send all (data_shards + parity_shards) shards as separate KCP packets
```

**Decoding** (receive path):
```
1. Collect received shards (any subset of total_shards)
2. If at least data_shards shards present: build linear system
3. Each received shard contributes a row to the matrix:
   - Data shard j: identity row (1 at column j)
   - Parity shard i: Vandermonde row (matrix[i][*])
4. Invert the matrix using Gauss-Jordan elimination over GF(2^8)
5. Reconstruct missing data shards
6. Reassemble, strip zero-padding, apply XOR
```

**Default configuration:** `data_shards=0, parity_shards=0` (FEC disabled). When enabled, typical values are `data_shards=10, parity_shards=3`.

### 1.3 Wire Format

Each KCP packet from kcp-go is either:
- A single raw data segment (when FEC disabled, XOR optional)
- One of N shards (when FEC enabled, each shard is a separate KCP packet with XOR already applied)

The KCP layer itself provides sequencing, retransmission, and fragmentation. kcp-go adds FEC across the data segments that KCP delivers.

## 2. Rust kcp Crate Architecture

The Rust `kcp` crate provides raw KCP protocol implementation only:

- KCP control block (conv, states, window, rto, etc.)
- `Kcp::input()` / `Kcp::output()` for packet IO
- `Kcp::send()` / `Kcp::recv()` for application data
- No FEC, no XOR, no session management

The `kcp` crate is purely the reliable transport protocol -- it delivers exactly what the application sends, in order, with ARQ retransmission.

## 3. Gap Analysis

| Feature | Go kcp-go | Rust kcp crate | Gap |
|---------|-----------|----------------|-----|
| Raw KCP protocol | Yes | Yes | None |
| Session management | Yes | No | kcp-go wraps KCP with session state |
| FEC (Reed-Solomon) | Yes | No | **Missing entirely** |
| XOR encryption | Yes | No | **Missing entirely** |
| Vandermonde matrix | Yes | No | **Missing entirely** |
| Gaussian elimination | Yes | No | **Missing entirely** |
| GF(2^8) arithmetic | Yes | No | **Missing entirely** |

**Impact:** Go KCP clients and servers cannot interoperate with Rust KCP clients/servers because:
- Go sends FEC shards + XOR-encrypted data
- Rust expects raw application data bytes

Even with `data_shards=0, parity_shards=0` (FEC disabled), Go may still apply XOR encryption, making the wire format incompatible.

## 4. Design of `kcp_compat` Module

### 4.1 Module Structure

```
frp-core/src/kcp_compat.rs
  ├── pub mod gf256          — GF(2^8) arithmetic (mul, pow, inv)
  ├── pub struct Fec         — Reed-Solomon encoder/decoder
  ├── pub struct XorBlock    — Repeating-key XOR cipher
  └── pub struct KcpCompatSession — Combined FEC + XOR session
```

### 4.2 GF(2^8) Arithmetic (`gf256` module)

Pure stand-alone GF(2^8) math using irreducible polynomial `0x11D`.

- `mul(a, b)`: Shift-and-add multiplication with polynomial reduction
- `pow(base, exp)`: Exponentiation by squaring
- `inv(a)`: Multiplicative inverse via `a^254` (since GF(2^8)* has order 255)

### 4.3 FEC (`Fec` struct)

- Constructor takes `data_shards` and `parity_shards`
- Pre-computes Vandermonde encoding matrix
- `encode(input)`: Returns `total_shards` Vecs (data copies + parity rows)
- `decode(shards)`: Gaussian elimination, reconstructs missing shards in-place
- `enabled()`: Returns false when both shard counts are 0

### 4.4 XOR (`XorBlock` struct)

- Constructor takes key bytes
- `process(data)`: XORs data in-place with repeating key
- `enabled()`: Returns false when key is empty

### 4.5 KCP Compat Session (`KcpCompatSession` struct)

Combines FEC and XOR into encode/decode operations:

- `encode_packet(data) -> Vec<Vec<u8>>`: Splits → XOR → FEC encode → shards
- `decode_packets(shards) -> Option<Vec<u8>>`: FEC decode → XOR → reassemble → strip padding
- No-op when both FEC and XOR are disabled (returns input as single shard)

### 4.6 Integration Points

The compat layer is a pure data transformation module. It does NOT handle:
- KCP connection setup / teardown
- UDP socket management
- KCP send/recv logic

Integration into frpc/frps KCP transport happens at the point where application data is handed to/from the raw KCP `send()`/`recv()` calls. When a KCP connection is established with a Go peer, wrap the data path:

```
send: app_data → KcpCompatSession::encode_packet → for each shard: kcp.send(shard)
recv: kcp.recv() → collect shards → KcpCompatSession::decode_packets → app_data
```

## 5. Testing Strategy

### Unit Tests (in `kcp_compat.rs`)
- GF(2^8): identity, distributivity, inverse, power laws
- FEC: encode/decode roundtrip with simulated loss
- FEC: disabled mode (no-op)
- XOR: roundtrip, empty key
- KcpCompatSession: full encode/decode with FEC + XOR

### Cross-Compat Tests (in `compat-test.sh`)
- `test_g2r_kcp`: Go frpc → Rust frps, KCP transport (with compat layer)
- `test_r2g_kcp`: Rust frpc → Go frps, KCP transport (with compat layer)

These were previously commented out because of the wire format gap. With the compat layer in place, they should work.

## 6. References

- Go kcp-go source: `github.com/xtaci/kcp-go` — `fec.go`, `xor.go`, `sess.go`
- Go reed-solomon: `github.com/klauspost/reedsolomon`
- Rust kcp crate: `kcp` on crates.io
- Irreducible polynomial: `x^8 + x^4 + x^3 + x^2 + 1` = 0x11D (AES polynomial)
