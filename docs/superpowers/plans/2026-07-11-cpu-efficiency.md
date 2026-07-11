# CPU Efficiency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Kill the encrypt-row 28x throughput cliff by replacing the byte-by-byte AES-128-CFB streaming loop with a wire-identical block-wise implementation; audit Snappy compress-side allocation and serde data-plane cost, optimizing only where a microbench proves it material.

**Architecture:** Three ordered targets from `docs/superpowers/specs/2026-07-11-cpu-efficiency-design.md`. C1 rewrites `CfbState::encrypt`/`decrypt` in `frp-core/src/cipher_stream.rs` to process 16-byte blocks (single feedback encrypt per block, vectorizable slice XOR, one `copy_from_slice` for feedback) while keeping the exact struct, API, and byte-for-byte output. C2 audits `encryption::compress` per-chunk allocation. C3 audits serde on the data plane. All changes wire-identical to Go frp v0.69.1.

**Tech Stack:** Rust, existing `aes` crate (AES-128 block cipher), `snap` (Snappy frame codec), criterion (`frp-core/benches/crypto_bridge.rs`), tokio duplex streams.

## Global Constraints

- **Wire-identical, no protocol change.** CFB-128 ciphertext, Snappy frame format, and JSON message format stay byte-for-byte identical to Go frp v0.69.1. C1 is a pure micro-optimization of an existing algorithm — output must match the current byte-loop for every input at every chunk/partial-block boundary.
- **No new dependencies** (CLAUDE.md). C1 uses existing `aes`; C2 uses existing `snap`; C3 changes no code.
- **No `unsafe`.** C1 stays in safe Rust.
- **Micro gate (primary):** `cargo bench -p frp-core` groups `cipher_stream/*` and `compression/*`. A change ships only if its targeted group improves and no other group regresses.
- **Macro gate (confirmation):** `bash scripts/throughput-baseline.sh` — any config row dropping >5% MB/s rejects the change.
- **Compat (mandatory after C1):** `bash scripts/compat-test.sh --verbose` must print a RESULTS line with 0 failures. A partial run (no RESULTS line, e.g. stale frps/frpc jamming ports) is NOT a pass — verify the RESULTS line explicitly.
- **Process (CLAUDE.md):** each task in a git worktree, implemented by a subagent, task-reviewed. Keep the `CfbState` struct fields and `refill`/`used` accounting unchanged.

---

### Task 1: Block-wise streaming CFB (C1)

The headline fix. `frp-core/src/cipher_stream.rs` `CfbState::encrypt` and `CfbState::decrypt` currently process one byte at a time (per-byte branch, scalar XOR, scalar feedback write). Rewrite them to process whole 16-byte blocks. This is a **behavior-preserving optimization**, so it is guarded by a characterization test (equivalence to an inline reference copy of the current byte-loop) rather than a red→green test — the test passes on the current code, then must still pass after the rewrite.

**Files:**
- Modify: `frp-core/src/cipher_stream.rs:55-76` (`CfbState::encrypt`, `CfbState::decrypt`)
- Test: `frp-core/src/cipher_stream.rs` (add to the `#[cfg(test)] mod tests` block at line 764)

**Interfaces:**
- Consumes: existing `CfbState` fields — `aes: Aes128`, `feedback: [u8; 16]`, `keystream: [u8; 16]`, `used: usize`; existing `fn refill(&mut self)`.
- Produces: `CfbState::encrypt(&mut self, data: &mut [u8])` and `CfbState::decrypt(&mut self, data: &mut [u8])` with identical signatures and identical output bytes to the current implementation. `CipherReader`/`CipherWriter` public API unchanged.

- [ ] **Step 1: Record baseline bench numbers**

Run: `cargo bench -p frp-core -- cipher_stream`
Expected: completes; note the reported time and throughput for `aes128cfb_encrypt_64_bytes`, `_1024_bytes`, `_65536_bytes` and the three `_decrypt_` counterparts. Record these six numbers in the task report — they are the before-side of the micro gate.

- [ ] **Step 2: Add the characterization test**

Add this test to the `mod tests` block (after line 764) in `frp-core/src/cipher_stream.rs`. It reimplements the current byte-loop as a local reference and asserts the real `CfbState` matches it across sizes that straddle block boundaries, including multi-chunk splits (which exercise cross-chunk `used` carry).

```rust
    // Reference byte-wise CFB (a copy of the pre-optimization algorithm).
    // The optimized block-wise CfbState must produce identical output.
    struct RefCfb {
        aes: aes::Aes128,
        feedback: [u8; 16],
        keystream: [u8; 16],
        used: usize,
    }
    impl RefCfb {
        fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
            use aes::cipher::{BlockEncrypt, KeyInit};
            let aes = aes::Aes128::new_from_slice(key).unwrap();
            let mut s = RefCfb { aes, feedback: *iv, keystream: *iv, used: 0 };
            s.aes.encrypt_block((&mut s.keystream).into());
            s
        }
        fn refill(&mut self) {
            use aes::cipher::BlockEncrypt;
            self.keystream = self.feedback;
            self.aes.encrypt_block((&mut self.keystream).into());
            self.used = 0;
        }
        fn encrypt(&mut self, data: &mut [u8]) {
            for byte in data.iter_mut() {
                if self.used >= 16 { self.refill(); }
                *byte ^= self.keystream[self.used];
                self.feedback[self.used] = *byte;
                self.used += 1;
            }
        }
        fn decrypt(&mut self, data: &mut [u8]) {
            for byte in data.iter_mut() {
                if self.used >= 16 { self.refill(); }
                let ct = *byte;
                *byte ^= self.keystream[self.used];
                self.feedback[self.used] = ct;
                self.used += 1;
            }
        }
    }

    // Deterministic pseudo-random fill (no rand dep needed in test).
    fn fill_pattern(buf: &mut [u8], seed: u64) {
        let mut x = seed | 1;
        for b in buf.iter_mut() {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
    }

    #[test]
    fn cfb_block_wise_matches_reference_encrypt() {
        let key = [7u8; 16];
        let iv = [0x11u8; 16];
        // Single-shot sizes straddling block boundaries.
        for size in [0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 4096] {
            let mut data = vec![0u8; size];
            fill_pattern(&mut data, size as u64 + 1);
            let mut got = data.clone();
            let mut want = data.clone();
            CfbState::new(&key, &iv).encrypt(&mut got);
            RefCfb::new(&key, &iv).encrypt(&mut want);
            assert_eq!(got, want, "encrypt mismatch at size {}", size);
        }
    }

    #[test]
    fn cfb_block_wise_matches_reference_decrypt() {
        let key = [7u8; 16];
        let iv = [0x11u8; 16];
        for size in [0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 4096] {
            let mut data = vec![0u8; size];
            fill_pattern(&mut data, size as u64 + 99);
            let mut got = data.clone();
            let mut want = data.clone();
            CfbState::new(&key, &iv).decrypt(&mut got);
            RefCfb::new(&key, &iv).decrypt(&mut want);
            assert_eq!(got, want, "decrypt mismatch at size {}", size);
        }
    }

    #[test]
    fn cfb_block_wise_matches_reference_chunked() {
        // Multi-chunk splits exercise cross-chunk `used` carry — the boundary
        // case a naive block rewrite gets wrong.
        let key = [42u8; 16];
        let iv = [0xABu8; 16];
        let splits: &[&[usize]] = &[
            &[1, 31, 4096],
            &[15, 1, 16, 17],
            &[16, 16, 16],
            &[7, 9, 100, 3, 4096],
            &[33, 33, 33],
        ];
        for chunks in splits {
            let total: usize = chunks.iter().sum();
            let mut plain = vec![0u8; total];
            fill_pattern(&mut plain, total as u64 + 7);

            let mut got = plain.clone();
            let mut want = plain.clone();
            let mut got_cfb = CfbState::new(&key, &iv);
            let mut want_cfb = RefCfb::new(&key, &iv);
            let mut off = 0;
            for &c in *chunks {
                got_cfb.encrypt(&mut got[off..off + c]);
                want_cfb.encrypt(&mut want[off..off + c]);
                off += c;
            }
            assert_eq!(got, want, "chunked encrypt mismatch for {:?}", chunks);

            // Round-trip: decrypting the ciphertext restores plaintext.
            let mut rt = got.clone();
            CfbState::new(&key, &iv).decrypt(&mut rt);
            assert_eq!(rt, plain, "round-trip mismatch for {:?}", chunks);
        }
    }
```

- [ ] **Step 3: Run the characterization test against the CURRENT byte-loop**

Run: `cargo test -p frp-core cfb_block_wise_matches_reference`
Expected: PASS (3 tests). This proves the reference is faithful and the guard is established before the rewrite. If it fails here, the reference copy is wrong — fix the test, not the production code.

- [ ] **Step 4: Rewrite `CfbState::encrypt` and `CfbState::decrypt` block-wise**

Replace the two methods at `frp-core/src/cipher_stream.rs:55-76` with:

```rust
    fn encrypt(&mut self, data: &mut [u8]) {
        let n = data.len();
        let mut i = 0;
        while i < n {
            if self.used >= 16 {
                self.refill();
            }
            // Fast path: at a fresh block boundary with a full block available,
            // XOR 16 keystream bytes against 16 data bytes (vectorizable) and
            // set the feedback register to the ciphertext block in one copy.
            if self.used == 0 && n - i >= 16 {
                let blk = &mut data[i..i + 16];
                for (b, k) in blk.iter_mut().zip(self.keystream.iter()) {
                    *b ^= *k;
                }
                self.feedback.copy_from_slice(blk);
                self.used = 16;
                i += 16;
            } else {
                // Partial block (leading carry or trailing remainder): byte-wise.
                let take = (16 - self.used).min(n - i);
                for j in 0..take {
                    let c = data[i + j] ^ self.keystream[self.used];
                    data[i + j] = c;
                    self.feedback[self.used] = c;
                    self.used += 1;
                }
                i += take;
            }
        }
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        let n = data.len();
        let mut i = 0;
        while i < n {
            if self.used >= 16 {
                self.refill();
            }
            if self.used == 0 && n - i >= 16 {
                let blk = &mut data[i..i + 16];
                // feedback = ciphertext (input), then plaintext = ct ^ keystream.
                self.feedback.copy_from_slice(blk);
                for (b, k) in blk.iter_mut().zip(self.keystream.iter()) {
                    *b ^= *k;
                }
                self.used = 16;
                i += 16;
            } else {
                let take = (16 - self.used).min(n - i);
                for j in 0..take {
                    let ct = data[i + j];
                    data[i + j] = ct ^ self.keystream[self.used];
                    self.feedback[self.used] = ct;
                    self.used += 1;
                }
                i += take;
            }
        }
    }
```

Rationale for correctness: the fast path only fires at `used == 0` (keystream fully fresh after `new`/`refill`), consuming exactly one block and leaving `used == 16`. `refill` is still deferred — it runs at the top of the next iteration only when more data remains, so a chunk ending exactly on a block boundary leaves `used == 16` with no refill, identical to the byte-loop. The partial branch handles a leading carry (`used` in 1..16 from a prior chunk) and the trailing remainder (`n - i < 16`).

- [ ] **Step 5: Run the characterization test against the new block-wise code**

Run: `cargo test -p frp-core cfb_block_wise_matches_reference`
Expected: PASS (3 tests). Equivalence to the old algorithm is preserved.

- [ ] **Step 6: Run the full cipher_stream + frp-core test suite**

Run: `cargo test -p frp-core cipher_stream` then `cargo test -p frp-core`
Expected: PASS. Existing round-trip, IV, partial-write, and Go-compat tests in `mod tests` stay green.

- [ ] **Step 7: Re-run the bench and confirm the micro gate**

Run: `cargo bench -p frp-core -- cipher_stream`
Expected: `aes128cfb_encrypt_*` and `aes128cfb_decrypt_*` throughput materially higher than Step 1 (especially `_65536_bytes`, dominated by full blocks). Record the after numbers. No group may regress. If encrypt did not improve, the fast path is not firing — stop and diagnose before committing.

- [ ] **Step 8: Run the cross-compat suite**

Run: `bash scripts/compat-test.sh --verbose`
Expected: prints a `RESULTS:` line with 0 failures. The encrypt/`use_encryption` Go↔Rust rows confirm wire compatibility. If the run stops early with no RESULTS line (stale processes jamming ports), kill leftover `frps`/`frpc`, free the ports, and re-run — a partial run is not a pass.

- [ ] **Step 9: Commit**

```bash
git add frp-core/src/cipher_stream.rs
git commit -m "perf(crypto): block-wise AES-128-CFB streaming cipher

Rewrite CfbState::encrypt/decrypt to process 16-byte blocks: single
feedback encrypt per block, vectorizable slice XOR, one copy_from_slice
for feedback. Wire-identical CFB-128 output (characterization test vs the
old byte-loop across boundary-straddling chunk splits). Targets the
encrypt-row throughput cliff from the CPU-efficiency baseline."
```

---

### Task 2: Snappy compress-side allocation audit (C2)

`encryption::compress` allocates a fresh `FrameEncoder::new(Vec::new())` per call — the sink `Vec` grows from empty. Investigate whether pre-sizing the output `Vec` measurably improves `compression/snappy_compress_*`. **Data decides:** ship the change only if the bench improves; otherwise revert and record the finding. No frame-format change (Go frp wire compat; `SnappyDecompressor` parses frame boundaries).

**Files:**
- Modify (conditionally): `frp-core/src/encryption.rs:49-59` (`compress`)
- Reference: `frp-core/benches/crypto_bridge.rs` `compression` group (already benches `snappy_compress_{64,1024,65536}_bytes`)

**Interfaces:**
- Consumes: `snap::write::FrameEncoder`, `snap::raw::max_compress_len`.
- Produces: `encryption::compress(data: &[u8]) -> Result<Vec<u8>, String>` — signature and output bytes unchanged.

- [ ] **Step 1: Record baseline bench numbers**

Run: `cargo bench -p frp-core -- compression`
Expected: completes; record `snappy_compress_64_bytes`, `_1024_bytes`, `_65536_bytes` and the three `snappy_decompress_*` numbers.

- [ ] **Step 2: Read the current `compress` and confirm the allocation shape**

Read `frp-core/src/encryption.rs:49-59`. Confirm it is:

```rust
pub fn compress(data: &[u8]) -> Result<Vec<u8>, String> {
    use snap::write::FrameEncoder;
    use std::io::Write;
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder
        .write_all(data)
        .map_err(|e| format!("snappy compress: {e}"))?;
    encoder
        .into_inner()
        .map_err(|e| format!("snappy compress into_inner: {e}"))
}
```

(If the exact wording differs, keep the existing error strings and control flow — only the sink `Vec` construction changes below.)

- [ ] **Step 3: Apply the pre-sized-buffer change**

Replace the sink construction so the output `Vec` is pre-sized to the Snappy frame upper bound, avoiding regrowth:

```rust
pub fn compress(data: &[u8]) -> Result<Vec<u8>, String> {
    use snap::write::FrameEncoder;
    use std::io::Write;
    // Pre-size the sink to the frame-format upper bound: raw max-compress-len
    // plus per-64KiB-block frame overhead (8-byte chunk header) and the stream
    // identifier. Avoids Vec regrowth during encoding. Frame bytes unchanged.
    let cap = snap::raw::max_compress_len(data.len())
        .saturating_add(data.len() / 65_536 * 8 + 24);
    let mut encoder = FrameEncoder::new(Vec::with_capacity(cap));
    encoder
        .write_all(data)
        .map_err(|e| format!("snappy compress: {e}"))?;
    encoder
        .into_inner()
        .map_err(|e| format!("snappy compress into_inner: {e}"))
}
```

- [ ] **Step 4: Run the encryption tests**

Run: `cargo test -p frp-core encryption` then `cargo test -p frp-core compress`
Expected: PASS. Round-trip `compress`→`decompress`/`SnappyDecompressor` tests confirm output bytes unchanged.

- [ ] **Step 5: Re-run the bench and decide**

Run: `cargo bench -p frp-core -- compression`
Expected: record after numbers. **Decision gate:**
- If `snappy_compress_*` improved (any size, no `snappy_decompress` regression): keep the change, go to Step 6.
- If no measurable improvement (within bench noise): revert the change with `git checkout frp-core/src/encryption.rs`, and record in the task report "pre-sizing not material — reverted, no change shipped." Then skip to the Task-2 completion (no commit).

- [ ] **Step 6: Commit (only if Step 5 kept the change)**

```bash
git add frp-core/src/encryption.rs
git commit -m "perf(compress): pre-size Snappy frame-encoder sink buffer

Avoid output Vec regrowth by pre-allocating to the frame-format upper
bound. Snappy frame bytes unchanged (round-trip tests green). Kept only
after snappy_compress bench showed measurable improvement."
```

---

### Task 3: serde data-plane audit (C3)

Confirm where serde runs on the data plane and record the YAGNI decision. Expected conclusion: control-plane messages are per-connection/per-event (not per-byte); the only per-packet serde path is `UDPPacket` JSON (`msg.rs`), which the TCP throughput baseline does not exercise. Deliverable is a written audit note — no code change unless the audit surfaces an unexpected per-byte hot path on the TCP data plane.

**Files:**
- Create: `docs/superpowers/notes/2026-07-11-serde-dataplane-audit.md`

**Interfaces:** none (audit only).

- [ ] **Step 1: Enumerate serde call sites on the data path**

Run: `grep -rn "serde_json::\(to_\|from_\)" frp-core/src frp-server/src frp-client/src | grep -v test`
Expected: a list of serialize/deserialize sites. Classify each as control-plane (login, proxy setup, ping/pong, dashboard) or data-plane (per byte/packet forwarded).

- [ ] **Step 2: Confirm the per-packet path**

Run: `grep -n "UDPPacket\|to_string\|from_str" frp-core/src/msg.rs | head`
Confirm `UDPPacket` is JSON-encoded per packet (base64 body) and that TCP/STCP/XTCP proxy bridging (`bridge_plain`/`bridge_encrypted`) carries raw bytes with **no** per-chunk serde. Cross-check that `bridge.rs` has no `serde_json` calls: `grep -c serde_json frp-core/src/bridge.rs` should be 0.

- [ ] **Step 3: Write the audit note**

Create `docs/superpowers/notes/2026-07-11-serde-dataplane-audit.md` recording: the enumerated call sites and their classification; the finding that the TCP/STCP/XTCP data plane carries raw bytes with zero per-chunk serde; that the only per-packet serde is `UDPPacket` JSON, exercised only by UDP proxies (not the TCP throughput baseline); and the decision — **no change (YAGNI); revisit only if UDP-proxy throughput enters scope**, at which point the target would be replacing per-packet JSON+base64 for `UDPPacket`. Reference the CPU-efficiency spec.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/notes/2026-07-11-serde-dataplane-audit.md
git commit -m "docs(perf): serde data-plane audit — control-plane only, YAGNI

TCP/STCP/XTCP bridging carries raw bytes with zero per-chunk serde; only
UDPPacket JSON is per-packet, exercised solely by UDP proxies outside the
throughput baseline. No code change; revisit if UDP throughput enters scope."
```

---

## Post-Task: Macro Confirmation + Baseline Refresh

After Tasks 1-3 are reviewed and complete, confirm the end-to-end win and refresh the committed baseline.

- [ ] **Step 1: Re-run the throughput matrix**

Run: `bash scripts/throughput-baseline.sh`
Expected: the `encrypt` row improves materially vs the committed baseline (target: from ~24 MB/s toward the plain/compress tier); `encrypt_compress` improves; **no other row regresses >5%**. If any non-encrypt row drops >5%, investigate before refreshing the baseline.

- [ ] **Step 2: Commit the refreshed baseline**

```bash
git add scripts/frp-stress/baselines/
git commit -m "chore(stress): refresh throughput baseline after CFB block-wise opt"
```

---

## Self-Review

- **Spec coverage:** C1 → Task 1; C2 → Task 2 (audit-first, data-gated); C3 → Task 3 (audit note). Micro gate (criterion) in every task's steps; macro gate (throughput-baseline) in Task 1 Step 7-8 region and the Post-Task section; compat-test.sh in Task 1 Step 8. All spec targets mapped.
- **Placeholders:** none — full code for the CFB rewrite, the characterization test, and the Snappy change; exact commands with expected output; exact commit messages.
- **Type consistency:** `CfbState::encrypt/decrypt(&mut self, data: &mut [u8])` signatures identical to current; `compress(data: &[u8]) -> Result<Vec<u8>, String>` unchanged; `refill`/`used`/`feedback`/`keystream` names match `cipher_stream.rs`.
- **Wire invariant:** Task 1's characterization test locks block-wise output to the byte-loop reference across boundary-straddling splits; compat-test.sh locks it to Go frp. Task 2 keeps frame format; Task 3 changes nothing.
