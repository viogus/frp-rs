# `release-perf` Profile A/B Audit

**Date:** 2026-11-08
**Context:** `[profile.release-perf]` was declared in the workspace `Cargo.toml`
but had never been measured. Its comment claimed "Binary is a few hundred KB
larger" — an unverified guess that turned out to be wrong by roughly 10x.
**Decision:** **Keep `release-perf` opt-in.** +84.5% `frps` / +83.5% `frpc` size
is not a marginal cost for a project whose differentiator is binary size. It is
a throughput-first build, not a better default.
**Measured tree:** `602910a5` (branch tip; the commits after it are docs-only)
**Toolchain:** rustc 1.98.1 `48a229cea` (2026-09-01)

## 1. Question

`[profile.release-perf]` is `inherits = "release"` with `opt-level = 3`
instead of `"z"` — same fat LTO, one codegen unit, stripped, `panic = "abort"`.
Two things were unknown:

1. What does it cost in binary size? The comment said "a few hundred KB".
2. What does it buy on the data plane, and where?

Both matter because the profile ships in `Cargo.toml`: if the size cost were
small it could become the default, and if the gain were small it could be
deleted.

## 2. Host & method

- Apple M2 / macOS arm64, one host, one day. All comparisons are same-host.
- **Load average 3.66 during the runs** — the laptop was busy with unrelated
  work for the whole session. See §8.
- Binaries built from `602910a5` with this tree's declared release profile
  (fat LTO, `opt-level = "z"` / `3`, `codegen-units = 1`, `strip`,
  `panic = "abort"`). Sizes read from the built files.
- Throughput and latency measured with the in-tree `frp-stress` harness via
  `scripts/throughput-baseline.sh` and `scripts/latency-baseline.sh` over
  loopback (`127.0.0.1`). Throughput covers six bridge configurations: `plain`,
  `encrypt`, `compress`, `encrypt_compress`, `mux`, `tls`; latency is
  steady-state RTT plus connection-setup percentiles (`steady`, `setup_cold`,
  `setup_warm`).
- **Alternating A/B**, never one build then the other: release, release-perf,
  release, release-perf. Throughput was measured at two points — 1 stream x
  10 s (two alternating runs, so two values per build) and 4 streams x 20 s
  (two alternating pairs, so two values per build). Latency: 2000 samples, one
  pair (`steady`, `setup_cold`, `setup_warm`).
- Per-run values are reported below rather than a median, so the run-to-run
  spread is visible.
- Rate unit: the harness computes `mbps` as bytes / 1024² / s, i.e. **MiB/s**.
  It printed "MB/s" when these runs were taken; the label was corrected in a
  separate change (`fix/mibps-label`). All throughput figures below use the harness's own
  unit; ratios (the actual result) are unaffected.

## 3. Size

| build | frps (bytes) | frpc (bytes) |
|---|---|---|
| `release` (`opt-level = "z"`) | 5,411,744 | 4,547,344 |
| `release-perf` (`opt-level = 3`) | 9,983,792 | 8,345,344 |
| `release` with `CARGO_PROFILE_RELEASE_OPT_LEVEL=2` | 9,257,056 | 7,849,856 |

vs `release`: **frps +4,572,048 B (+84.5%)**, **frpc +3,798,000 B (+83.5%)**.
Sizes are decimal MB (5,411,744 B = 5.16 MiB), the convention CLAUDE.md's
"~5.3 MB" figure uses. `opt-level = 2` is +71.1% / +72.6% — 9.26 MB, only
0.72 MB (7%) below `-O3`, so it is not a cheaper middle ground.

## 4. Throughput — 1 stream x 10 s (MiB/s)

| config | release #1 | release #2 | release-perf #1 | release-perf #2 |
|---|---|---|---|---|
| `plain` | 370.0 | 332.8 | 394.3 | 398.3 |
| `encrypt` | 213.2 | 209.0 | 257.2 | 253.1 |
| `compress` | 282.3 | 275.7 | 335.7 | 350.3 |
| `encrypt_compress` | 272.2 | 277.2 | 335.1 | 343.6 |
| `mux` | 296.5 | 292.6 | 296.9 | 317.1 |
| `tls` | 373.3 | 370.6 | 395.4 | 374.0 |

## 5. Throughput — 4 streams x 20 s (MiB/s)

| config | release #1 | release #2 | release-perf #1 | release-perf #2 |
|---|---|---|---|---|
| `plain` | 471.3 | 450.5 | 611.9 | 526.7 |
| `encrypt` | 268.9 | 299.8 | 368.3 | 428.4 |
| `compress` | 416.6 | 459.1 | 521.4 | 617.9 |
| `encrypt_compress` | 452.5 | 460.2 | 520.7 | 454.4 |
| `mux` | 252.8 | 314.9 | 311.0 | 341.7 |
| `tls` | 491.5 | 391.6 | 486.9 | 448.5 |

## 6. Latency (µs, 2000 samples)

| mode | stat | release | release-perf |
|---|---|---|---|
| `steady` | p50 | 218.208 | 200.708 |
| `steady` | p95 | 294.167 | 234.833 |
| `steady` | p99 | 538.125 | 478.333 |
| `steady` | max | 642.916 | 806.875 |
| `setup_cold` | p50 | 1009.875 | 749.667 |
| `setup_cold` | p95 | 2388.209 | 860.583 |
| `setup_cold` | p99 | 6776.25 | 1743.375 |
| `setup_cold` | max | 41380.292 | 5576.875 |
| `setup_warm` | p50 | 843.083 | 743.791 |
| `setup_warm` | p95 | 1201.833 | 856.625 |
| `setup_warm` | p99 | 2182.875 | 2280.25 |
| `setup_warm` | max | 15178.959 | 10517.625 |

No latency regression that one unrepeated pair can establish. `steady`
p50/p95/p99 are lower, but the tails are mixed: `steady` max (806.875 vs
642.916 µs, +25.5%) and `setup_warm` p99 (2280.25 vs 2182.875 µs, +4.5%) are
*higher* on `release-perf`. The `setup_cold` tail (41,380.292 µs on `release`
vs 5,576.875 µs on `release-perf`) looks like host interference rather than a
compiler difference — a hypothesis, not a finding, from a single pair.

## 7. Verdict

**`release-perf` stays opt-in.** Size is this project's differentiator; +84% is
not a marginal cost, and `opt-level = 2` is not a cheaper middle ground
(9.26 MB, 0.72 MB below `-O3`). It is for throughput-first deployments.

Which rows move: the gain is **not specific to one codec**. `plain` — no
encryption, no compression — gains +6.6-19.7% at 1 stream and +23.5% (mean) at
4 streams, the same order as `encrypt`, so most of the win is the data-plane
buffering/copy/framing code, not one primitive. At 4 streams
the rows that clearly move are `encrypt` (+40.1% mean) and `compress` (+30.1%
mean); the rows that do not are `tls` (+5.9% mean) and `encrypt_compress`
(+6.8% mean, one pair negative). Note what does *not* appear here:
`use_encryption` is **AES-128-CFB**, implemented in-tree
(`frp-core/src/cipher_stream.rs`), not an AEAD primitive;
XChaCha20-Poly1305 / AES-256-GCM are selected only for the V2 **control**
connection (`frp-core/src/v2_handshake.rs:205-218` prefers AES-256-GCM), which
carries no bulk data.

How much of that the noise can carry: the direction holds at the config level —
all twelve config medians are higher on `release-perf` — but not on every pair.
At **1 stream** the two builds separate on every configuration (criterion: the
lower `release-perf` value above the higher `release` value — but `mux` 296.9 vs
296.5 and `tls` 374.0 vs 373.3 clear it by 0.1-0.2%, inside this host's noise,
so do not read those two as gains). At **4 streams** the runs overlap on
`encrypt_compress` (454.4 below `release`'s 460.2), `mux` (311.0 below 314.9)
and `tls` (486.9 below 491.5). The **magnitude is not a contract** — individual
4-stream rows spread by up to ~25% between the two runs (`tls` 491.5 vs 391.6,
`mux` 252.8 vs 314.9), and this host was loaded, so read the encrypted/
compressed gains as a rough range, not a benchmark.

## 8. Caveats

- **Host load.** Load average 3.66 throughout — the measurement host was doing
  other work. Alternation is what makes the direction readable; a quiet host
  would tighten the magnitudes. Numbers here are not gate thresholds.
- **One host, one day, loopback.** macOS arm64. Cross-platform magnitudes,
  especially the snappy/XChaCha split against `-Oz`, are unmeasured.
- **One latency pair**, 2000 samples, not repeated. Treat §6 as direction only.
- **Only `-Oz` vs `-O3` (and sizes for `-O2`)**. Other profile knobs (thin vs
  fat LTO, `codegen-units`, `opt-level = 1`, target-cpu) were not measured.
- **Sizes are this host's**, from the declared release profile in `Cargo.toml`;
  CI writes its own `lto=false`/`opt-level=2` overrides, so CI artifact sizes
  are not comparable (see CLAUDE.md).

## 9. Reproduction

```bash
# throughput-first build
cargo build --profile release-perf -p frps -p frpc

# 4 streams x 20 s; the harness is always built from this tree
FRPS_BIN="$PWD/target/release-perf/frps" FRPC_BIN="$PWD/target/release-perf/frpc" \
  bash scripts/throughput-baseline.sh 20 4

# sizes only: opt-level=2 through the release profile's own env override
CARGO_PROFILE_RELEASE_OPT_LEVEL=2 cargo build --release -p frps -p frpc
```

Latency uses the same `FRPS_BIN`/`FRPC_BIN` prefix with
`bash scripts/latency-baseline.sh 2000`; restore the default build with
`cargo build --release -p frps -p frpc` between runs.

**Both baseline scripts rewrite their per-host file**
(`scripts/frp-stress/baselines/throughput-<hostname>.jsonl`, and the latency
equivalent) on every run, so an A/B that alternates binaries would otherwise
leave only the last build's numbers and silently replace the committed
baseline. Save each run's jsonl before switching binaries, or point the run at
a scratch path:

```bash
OUT=/tmp/ab-release.jsonl bash scripts/throughput-baseline.sh 10 1
OUT=/tmp/ab-release-perf.jsonl FRPS_BIN="$PWD/target/release-perf/frps" \
  FRPC_BIN="$PWD/target/release-perf/frpc" bash scripts/throughput-baseline.sh 10 1
```

This A/B needed each run's jsonl saved aside before switching binaries; the
`OUT` override is what replaces that habit with a flag.
