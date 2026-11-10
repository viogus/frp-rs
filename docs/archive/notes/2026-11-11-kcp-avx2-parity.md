# KCP FEC: a vectorised parity pass, +19% on a bulk stream

**Question.** [`2026-11-11-kcp-stream-vs-go.md`](2026-11-11-kcp-stream-vs-go.md)
measured KCP bulk streams at 49 MiB/s against Go's 103, with a debuginfo profile
putting **16.3%** of frps samples in `KcpSession::fec_encode_output`. The
multiply itself is already a table lookup (#596), so what is left is the shape of
the loop: one 256-entry lookup and one XOR per byte, per data shard — ten
dependent lookups per output byte for kcp-go's 10+3 group. Go's
`klauspost/reedsolomon` does the same encode with `VPSHUFB`.

## What changed

`frp-core/src/kcp_compat.rs` gained a nibble-table vector path:

- `Fec::new` builds, per (parity, data) coefficient, `lo[16]` where
  `lo[n] = coef * n` and `hi[16]` where `hi[n] = coef * (n << 4)` — 32 bytes per
  coefficient (960 B for 10+3). Because a byte is `(b & 0x0f) ^ ((b >> 4) << 4)`,
  `coef * b = lo[b & 0x0f] ^ hi[b >> 4]`.
- `xor_mul_into` runs that as two `VPSHUFB` lookups and an XOR per 32 bytes
  (`xor_mul_avx2`, `#[target_feature(enable = "avx2")]`), detected once with
  `is_x86_feature_detected!`.
- Lengths below 32 bytes and CPU/targets without AVX2 keep the existing
  scalar 256-entry table path unchanged, so aarch64 and older x86 pay nothing
  for this change.

`encode` and `encode_parity` both call the shared helper, so the two cannot
drift apart.

## Result

Linux VM (4 vCPU AMD EPYC-Milan, Debian 13, loopback), 2048 MiB one-way stream,
`tcpMux` on, interleaved base/patched runs:

| shape | base | vectorised | ratio | CPU-s (frps+frpc) |
|---|---|---|---|---|
| 1 flow | 48.3 / 49.1 / 50.0 MiB/s | 57.7 / 59.5 / 58.2 MiB/s | **+19%** | 97.2 → 81.4 (**−16%**) |
| 4 flows | 48.2 / 48.5 MiB/s | 58.7 / 60.3 MiB/s | **+23%** | 95.9 → 79.8 (**−17%**) |

For scale, the same host measures **76-77 MiB/s** with FEC disabled outright
(parity set to 0 in the codec) — that is the ceiling a perfect encoder would
reach with the 30% packet saving still in place, and it is not attainable: Go
pays the FEC bandwidth too, and Go measures 103 MiB/s with FEC on.

So the encode was worth roughly half of the total frp-rs-vs-Go gap: 49 → 58
MiB/s against 103.

## Correctness

- `encode_parity_matches_bitwise_reference` and the `klauspost` golden vector
  still pass — the vector path is byte-identical to the bit-serial reference for
  the 10+3, 4+2 and 3+2 configurations.
- New `vector_encode_matches_scalar_for_all_lengths` compares the vector path
  against the scalar table path at lengths 1, 5, 16, 31, 32, 33, 63, 100, 1326
  and 1327, which covers both sides of the 32-byte vector width and the odd tail
  of a 1326-byte KCP segment.
- `cargo test -p frp-core --all-features --lib kcp_compat`: 17 passed on x86_64
  (where the vector path executes) and on aarch64 (where the scalar path does).

## What is left

At 58 MiB/s against Go's 103 the bulk KCP stream is still ~1.8× behind, and the
remaining cost is not the parity math — the profile has to be re-taken on this
build to see what moved up. The other measured cost (`clock_gettime` ~3.6%,
wake-up spin locks) points at per-packet scheduling in the driver task, which is
the untested half of the `TODO.md` item.

## Limits

- One host, one transport shape (bulk one-way stream over loopback). The
  ping-pong shape was not re-measured; it was already far ahead of Go.
- x86_64 only. aarch64 keeps the scalar table path — `vqtbl1q_u8` would be the
  equivalent, and nothing here measures whether it pays as well.
- The vector path needs `src.len() >= 32`; shorter shards fall back, which is
  why the correctness test covers both sides of that boundary.

## Reproduce

```
# on the host, both binaries from v0.72.0 sources
bash /root/bench/kcp3.sh rs rs base 1 2048 true      # table path
bash /root/bench/kcp3-avx2.sh rs rs avx2 1 2048 true # vector path (same harness)
```

`kcp3.sh` prints `MiB/s` and the CPU ticks of both processes from
`/proc/<pid>/stat`.
