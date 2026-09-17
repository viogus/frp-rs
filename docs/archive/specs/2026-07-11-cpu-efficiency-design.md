# CPU Efficiency — Design

**Date:** 2026-07-11
**Status:** Approved (brainstorming), pending implementation plan
**Scope:** Sub-project 4 of a 4-axis performance program (throughput → latency → memory → **CPU**). Sub-project 1 (throughput) is complete and established the baseline this spec targets. Latency and memory remain separate cycles.

## Problem

The throughput baseline (`scripts/frp-stress/baselines/throughput-*.jsonl`, 10s / 1-stream, Mac loopback) exposed one dominant CPU cliff:

| config | MB/s | vs plain |
|--------|------|----------|
| plain | 693 | 1.0x |
| tls | 595 | 0.86x |
| compress | 522 | 0.75x |
| mux | 518 | 0.75x |
| encrypt_compress | 251 | 0.36x |
| **encrypt** | **24.3** | **0.035x (~28x slower)** |

On loopback the bridge is CPU-bound, not I/O-bound, so MB/s directly reflects CPU cost per byte. The `encrypt` row is a **28x** cliff — far worse than encryption should cost on hardware-AES machines.

Root cause (confirmed by reading `frp-core/src/cipher_stream.rs:55-76`): the streaming AES-128-CFB cipher processes data **one byte at a time**:

```rust
fn encrypt(&mut self, data: &mut [u8]) {
    for byte in data.iter_mut() {
        if self.used >= 16 { self.refill(); }  // branch per byte
        *byte ^= self.keystream[self.used];    // scalar XOR, no SIMD
        self.feedback[self.used] = *byte;      // scalar feedback write
        self.used += 1;
    }
}
```

Per-byte branch, scalar XOR, and scalar feedback writes defeat the vectorized XOR the compiler could emit and add ~16x loop overhead around each `encrypt_block`. Note the one-shot control-plane path (`encryption.rs:23-42`) already uses the optimized `cfb_mode::Encryptor` crate — **only the streaming bridge path hand-rolls the slow loop.**

Two secondary data-plane CPU paths were named in scope:
- **Snappy compress** (`encryption.rs:49-59`): allocates a fresh `FrameEncoder` + output `Vec` per chunk. The `compress` row costs ~25% vs plain.
- **serde JSON** (`msg.rs`): control-plane messages (Login/NewProxy/Ping) are low-frequency — negligible per-byte cost. The only per-packet data-plane serde is `UDPPacket` JSON encoding (`msg.rs:930`), which the TCP-echo baseline does not exercise.

## Goals

1. Eliminate the streaming AES-128-CFB per-byte cliff with a **wire-identical** block-wise rewrite.
2. Reduce Snappy compress-side allocation churn **only where a microbench proves it material**.
3. Audit the serde data-plane cost and either optimize or explicitly record it as YAGNI.

Non-goal: latency, memory footprint (separate sub-projects). **Non-goal: changing the wire protocol** — CFB-128 output, Snappy frame format, and JSON message format all stay byte-identical to Go frp v0.69.1. Non-goal: switching cipher suites (AES-CFB is fixed by Go-frp compat).

## Measurement

Two-tier, matching the throughput sub-project's discipline:

- **Micro (primary gate):** existing criterion groups in `frp-core/benches/crypto_bridge.rs` — `cipher_stream/aes128cfb_encrypt_N_bytes`, `aes128cfb_decrypt_N_bytes`, `compression/snappy_compress_N_bytes`, `snappy_decompress_N_bytes`. Capture `cargo bench -p frp-core` numbers before each change, keep the change only if the targeted group improves and no other group regresses. These isolate CPU cost from loopback/scheduler I/O noise.
- **Macro (confirmation):** `bash scripts/throughput-baseline.sh` `encrypt` / `encrypt_compress` / `compress` rows — end-to-end confirmation that the micro win reaches real throughput. Regression threshold: any config dropping >5% MB/s rejects the change (same gate as the throughput baseline).

## Update (post-T1): root-cause correction

The block-wise CFB rewrite (C1) landed correct and wire-identical but delivered **no encrypt-row throughput gain** — the macro gate showed 24.3 → 25.3 MB/s (noise). The original hypothesis (byte-by-byte loop = the 28x cliff) is **falsified**. Measurement located the true cause: the `aes` crate runs its **software backend** on aarch64. `cipher_stream/aes128cfb_encrypt_65536` measures 52 MiB/s on the software backend vs **547 MiB/s** with `RUSTFLAGS='--cfg aes_armv8'` (+948%). x86_64 already autodetects AES-NI, so the cliff is aarch64-specific (Apple Silicon / Graviton / ARM SBC); the baseline was taken on Mac aarch64.

**Added target C4 (the real fix):** upgrade `aes` 0.8→0.9 + `cfb-mode` 0.8→0.9 (both `cipher` 0.5.2). aes 0.9 does runtime ARMv8-AES detection (no `--cfg`, portable software fallback). aes 0.9 is already in-tree via russh, so no new crate. C1 is retained as a correct, wire-identical, no-regression cleanup. See the implementation plan Task 4.

## Architecture — Optimization Targets (ordered by benefit/risk)

### C1 — Block-wise streaming CFB (high benefit, low risk) — the headline fix

`frp-core/src/cipher_stream.rs`. Rewrite `CfbState::encrypt` and `CfbState::decrypt` to process whole 16-byte blocks:

- Encrypt the feedback register once per block (unchanged `aes::Aes128::encrypt_block`).
- XOR the 16-byte keystream against a 16-byte slice of the data (slice-vs-slice XOR the compiler can auto-vectorize).
- Set the next feedback register with a single `copy_from_slice` of the 16-byte ciphertext block (encrypt) or the 16 input ciphertext bytes (decrypt).
- Handle a leading partial block (when `used > 0` mid-block from a prior chunk) and a trailing partial block (input length not a multiple of 16) with the existing byte-wise path.

Keep the exact `CfbState` struct fields, the `refill`/`used` accounting semantics across chunk boundaries, and the public `CipherReader`/`CipherWriter` API. CFB feedback is serial, so block encryption cannot be parallelized across the stream — the single `encrypt_block` per block stays; the win is removing per-byte branch/XOR/feedback overhead.

**Wire invariant:** for any input, byte-for-byte identical output to the current byte-loop, at every chunk boundary and partial-block split. This is a pure micro-optimization of an existing algorithm.

Verify: `cipher_stream/aes128cfb_encrypt|decrypt` benches improve materially; unit test asserting new block-wise output equals old byte-wise output across chunk splits that straddle block boundaries (e.g. write 1 byte then 31 bytes then 4096 bytes); existing round-trip and Go-compat tests stay green; `bash scripts/compat-test.sh` encrypt paths pass; `encrypt` throughput row improves with no other row regressing >5%.

### C2 — Snappy compress-side allocation (data-driven, keep only if measured) — DATA DECIDES

`frp-core/src/encryption.rs:49-59`. `compress()` builds a new `FrameEncoder::new(Vec::new())` per call. Investigate whether the per-chunk output `Vec` allocation is material via `compression/snappy_compress_N_bytes`.

If material: pre-size the output `Vec` (upper-bound from `snap::raw::max_compress_len`) and/or reuse a pooled buffer, **without changing the Snappy frame wire format** (Go frp expects the frame format; `SnappyDecompressor` on the peer parses frame boundaries). If not material, record the finding and make **zero change** — no blind optimization.

Verify: `snappy_compress` bench improves if changed; `snappy_decompress` and compat `compress` paths unchanged; `compress` throughput row not regressed.

### C3 — serde data-plane audit (audit, likely zero change) — YAGNI GATE

Audit serde usage on the data plane. Expected finding: control-plane messages are per-connection/per-event (not per-byte), and the only per-packet path is `UDPPacket` JSON — which the TCP throughput baseline does not measure. If confirmed, record "serde is control-plane only; no per-byte data-plane cost on TCP; UDP-proxy throughput not in scope" and make **zero change**. Only if UDP-proxy throughput is later brought into scope does this become actionable.

Verify: written audit conclusion in the task report; no code change unless the audit surfaces an unexpected per-byte hot path.

## Approach Decisions (from brainstorming)

- **CFB: block-wise hand-rolled (Approach A)**, not crate delegation (B) or micro-opt/unsafe (C). Rationale: CFB is inherently serial so delegating to `cfb-mode` gives no algorithmic edge, and our arbitrary-length `read()` chunks would force re-implementing the partial-block carry anyway — any boundary bug is a wire-compat break. A keeps the exact struct/API, needs no new dep, no `unsafe`, and the existing bench proves it.
- **Snappy & serde: audit-first**, not committed reshapes. Mirrors the throughput T2 "data decides" rule — no change ships without a microbench justifying it.

## Verification + Regression Gate

- **Per-item:** micro bench (primary) + throughput-baseline macro (confirmation). >5% MB/s drop on any row, or a regressed bench group, rejects the change.
- **Process discipline (CLAUDE.md, mandatory):** each C-item done in a git worktree, implemented by a subagent, reviewed per-task, and — since C1 touches the encryption/transport plane — followed by `bash scripts/compat-test.sh` (verify the RESULTS line shows 0 failures; a partial run is not a pass) to confirm Go↔Rust wire compatibility.
- **No new dependencies** (CLAUDE.md): C1 uses the existing `aes` crate; C2 uses existing `snap`; C3 changes nothing.
- **Tests:** C1 gets a wire-equivalence unit test (block-wise output == byte-wise output across boundary-straddling chunk splits) plus the existing round-trip/compat suite.

## Out of Scope / Follow-up

- Latency and memory axes — separate specs.
- Protocol/wire changes — none. CFB-128, Snappy frame format, JSON all byte-identical to Go frp.
- Cipher-suite change (e.g. AES-GCM/CTR for parallelism) — a wire-protocol change, out of scope; the V2 AEAD path (`crypto.rs`) is a separate, already-implemented protocol, not a swap-in for V1 CFB.
- UDP-proxy serde optimization — deferred unless UDP throughput enters scope.
