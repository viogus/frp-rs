# KCP throughput: pre-computed GF(2^8) tables for FEC parity

Measured 2026-11-09 on macOS 26.2 (arm64, Apple M2), loopback, release build.

## Symptom

The protocol matrix has always reported KCP roughly an order of magnitude
below TCP (`kcp-plain` 22.25 MiB/s against `tcp-plain` 526.90 MiB/s, same run,
same host, same harness). Two questions followed: is that KCP's own
acknowledgement overhead, or is something in frp-rs doing avoidable work?

The configuration is not the answer: both sides already use Go frp's
aggressive defaults (`nodelay` 1, `interval` 20, `resend` 2, `nc` 1, MTU 1350,
windows 1024/1024, FEC 10/3) — see `frp-core/src/kcp/mod.rs`.

## Where the time went

`Fec::encode_parity` builds one parity shard per output byte by XOR-ing
`data_shards` products:

```text
for each parity shard:
    for each byte position:
        for each data shard:
            sum ^= gf256::mul(coef, input[byte])
```

`gf256::mul` is a bit-serial Russian-peasant multiply — eight shift/XOR rounds
per call. With kcp-go's 10 data + 3 parity group that is 10 × 8 = 80 rounds
per parity byte, 240 rounds per byte position across the three parity shards.
Everything else in the path (packet counts, MTU, syscalls) was exonerated by
the MTU experiment below, which moved throughput by under 1%.

## Change

The coefficients in `encode_matrix` are fixed at construction, so all 256
products per coefficient are pre-computed once into
`mul_tables[(parity * data_shards + data) * 256 + byte]` (30 × 256 B ≈ 7.5 KiB
for the default group). The hot loop becomes one lookup plus XOR, and is
reordered data-shard-outer/byte-inner so each table is read repeatedly from
cache.

The loss-recovery path uses the same trick with tables built per call from the
inverse matrix row, but only for blocks of at least 256 bytes — below one
table's worth of bytes the table build costs more than it saves, so short
blocks keep the bit-serial multiply.

`gf256::mul` itself is unchanged; it still builds the encode matrix and the
per-call decode tables, and the new tests pin table-vs-multiply equality, so
the wire format is untouched.

## Result

Same binary pair except for this change, interleaved, 64 KiB ping-pong over a
KCP tunnel, frps + frpc on loopback, 5 s per sample:

| case | before | after | change |
|---|---|---|---|
| 1 flow, no `tcpMux` | 20.7 / 21.0 / 20.8 MiB/s | 63.7 / 62.7 / 62.6 MiB/s | **3.0×** |
| 4 flows, no `tcpMux` | 40.2 MiB/s | 86.6 MiB/s | 2.15× |
| 1 flow, `tcpMux` on | 22.3 MiB/s | 61.1 MiB/s | 2.7× |

CPU time is essentially unchanged: 5.9 s / 6.1 s per side over a 5 s sample
before, 6.4 s / 6.3 s after (frps / frpc). The same cores now move three times
the bytes, so the multiply really was the dominant cost rather than a
scheduling artefact.

MTU control (before the change, FEC on): 1350 → 20.8 MiB/s, 1400 → 20.7 MiB/s.
Packet count is not the limiter.

## Go frp, measured (same harness, same container)

Earlier drafts of this note said no Go number was obtainable. That is a property
of this macOS host, not of Go frp, and it had two separable causes:

1. **A config default, not a bug.** A Go `frps` serves KCP with
   `transport.tcpMux = true` by default. A Go `frpc` configured with
   `tcpMux = false` never completes a KCP login (the same mismatch fails over TCP
   with `connect to server error: EOF`), which reads like "KCP does not connect".
2. **A darwin client hang.** With `tcpMux` matched, the v0.72.0 darwin `frpc`
   still parks before login: `SIGQUIT` puts the main goroutine in `select` at
   `client/connector.go:247`, while a bare `kcp-go` v5.6.73 echo over the same
   port completes. The Linux build of the same release connects in under a
   second.

So both implementations were measured in `debian:bookworm-slim`
(`--platform linux/arm64`, same host), both at v0.72.0, one harness:

| workload | Go frp v0.72.0 | frp-rs 0.72.0 |
|---|---|---|
| 1 flow, one-way 256 MiB stream | 121.2 MiB/s | **149.5 MiB/s** |
| 4 flows, one-way 256 MiB stream | 128.9 MiB/s | **150.7 MiB/s** |
| 1 flow, 64 KiB ping-pong | 4.6 MiB/s | 65.4 MiB/s |
| 4 flows, 64 KiB ping-pong | 25.3 MiB/s | 144.3 MiB/s |

"Stream" is a client writing 256 MiB through the proxy to a sink that only reads,
so it measures the path ceiling; "ping-pong" is one 64 KiB write followed by a
64 KiB read, so it measures the cost of a round trip. The ping-pong gap is a
*shape* difference, not extra work: Go's stream row moves 121 MiB/s through the
same code, so its ~14 ms round trip is where it flushes, not what it computes.
The stream row is the honest headline — **+23%** — and it is consistent with the
table above removing a cost Go never had: `kcp-go` delegates FEC to
`klauspost/reedsolomon`, which ships NEON/SSE assembly, so parity was the goal
here rather than a win.

Absolute figures are container-bound and must not be compared with the macOS
rows above: the same container measured frp-rs at 65.4 MiB/s ping-pong where
macOS measures 62.9, so only the Go-versus-Rust ratio inside one container is
meaningful.

## Verification

- `cargo test -p frp-core --all-features --lib` — 1260 passed.
- New tests: `mul_tables_match_bitwise_field_multiply` (all coefficients, all
  256 byte values, four shard shapes), `encode_parity_matches_bitwise_reference`
  (four shapes including 1350- and 1299-byte blocks) and
  `reconstruct_recovers_data_shards_on_both_paths` (64/16/300-byte blocks, so
  both decode paths run) and `disabled_codec_builds_no_tables`.
- `scripts/compat-test.sh` was **not** run locally: on this macOS host a Go frp
  v0.72.0 KCP client does not complete a dial (see the section above for the two
  causes — a `tcpMux` default mismatch, then a darwin client hang), so no Go KCP
  scenario can execute here. CI's `compat.yml` KCP scenarios are the gate.
- `cargo fmt --all -- --check` and
  `cargo clippy -p frp-core --all-targets --all-features` clean.

## Reproduce

No harness ships for this shape, so the numbers came from a throwaway
ping-pong client: N threads, each sending 64 KiB and reading the 64 KiB echo
through the proxy port for D seconds. `frp-stress`'s `throughput` scenario is
not usable over KCP *with the throwaway configs below* — every run failed with
`early eof` while the same 64 KiB exchange succeeds over a plain socket through
the same tunnel. (Correction, 2026-11-09 evening: `scripts/protocol-matrix.sh`
measures the same scenario over KCP without trouble at 65 MiB/s, so the failure
is a property of this note's hand-written configs, not of the scenario. The
matrix's config is the one to copy.) So the
scenario's own handshake is the suspect, not the KCP data path.

## Limits

- Loopback only. Cross-implementation parity for this change rests on the
  unchanged wire format, the unchanged `encode_matrix`, and the equality tests,
  plus CI's KCP compat scenarios; the Go-versus-Rust throughput comparison above
  ran in a Linux container because this host's darwin Go client does not dial.
- The 4-flow figure is one sample per arm.
