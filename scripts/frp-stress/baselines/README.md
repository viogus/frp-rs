# Throughput baselines

`throughput-<hostname>.jsonl` records MB/s per bridge configuration,
produced by `scripts/throughput-baseline.sh`. Numbers are **host-specific**
(CPU, kernel, NIC) — compare a change only against a baseline captured on
the SAME host. Regenerate the baseline before starting a Phase 2 change,
then re-run after and diff: any config dropping >5% MB/s rejects the change.

## Matrix

One JSON line per bridge configuration:

| label | bridge path |
|-------|-------------|
| `plain` | `copy_bidirectional`, no encryption/compression/mux |
| `encrypt` | AES-128-CFB encrypted bridge (`use_encryption`) |
| `compress` | Snappy-compressed bridge (`use_compression`) |
| `encrypt_compress` | compress → encrypt |
| `mux` | yamux stream multiplexing (`tcp_mux`) |
| `tls` | TLS control+work transport |

## Latency and memory baselines

Besides the throughput matrix, this directory also tracks:

- `latency-<hostname>.jsonl` — per-message RTT stats (mean / p50 / p95 / p99 /
  max µs across `steady` and `setup_cold`/`setup_warm` modes, 2000 samples),
  produced by `scripts/latency-baseline.sh`.
- `memory-<hostname>.jsonl` — live-heap bytes and RSS per mode
  (`idle_plain`, `idle_encrypt`, `churn_plain`, …) at 500 connections,
  produced by `scripts/memory-baseline.sh`.
- `rss-soak-<hostname>.jsonl` — a **head-to-head RSS time series**: frp-rs
  `frps`+`frpc` and the Go frp release `frps`+`frpc` run concurrently with the
  same proxy set and the same traffic (paced short-lived connection churn plus
  a few rate-capped long-lived byte streams), sampled every 30–60 s for hours,
  produced by `scripts/rss-soak.sh`. Unlike `memory-<hostname>.jsonl` this uses
  plain release binaries and reads RSS only, because the mem-profile allocator
  counters do not exist in Go. It is the evidence for (or against) the
  "no GC ⇒ stable RSS" positioning claim; `memory-baseline.sh` remains the
  frp-rs-only, allocator-counter baseline.

### `rss-soak-<hostname>.jsonl` format

One JSON object per line, in three parts:

| `kind` | contents |
|--------|----------|
| `meta` | one first line: host, platform, cores, frp-rs version + git sha, Go frp version + dir, the four binary `sha256` values, the traffic recipe, the ports, and an explicit `caveats` list |
| `sample` | one per interval: `elapsed_s`, UTC `ts`, `load1`, the host-wide `time_wait` socket count, and RSS in KB for all four processes (`null` when a process was momentarily unreadable) |
| `summary` | one last line: per-process `first`/`last`/`min`/`max`/`mean`/`first_hour_mean`/`last_hour_mean`/`growth_pct_first_to_last`, achieved `traffic` per side, load and TIME_WAIT ranges, and `aborted` |

**An artifact with no trailing `summary` line is an incomplete run.** The
summary's `aborted` field is `null` for a completed window; otherwise it names
the fault (a process that died, a propagation signal, or traffic that moved
nothing). `scripts/rss-soak.sh` exits non-zero in that case, and also when
either side's churn completed no echo round trips or its steady stream moved no
bytes — a flat RSS line is only evidence if load was actually delivered on both
sides.

What the series does and does not establish:

- **Does**: how each implementation's resident memory moves over hours on one
  host under identical *offered* load, sampled side by side.
- **Does not**: prove absence of leaks. RSS is not live heap — it includes
  allocator retention, page-fault and page-cache effects, and memory the OS has
  not reclaimed, so a flat line is consistent with both "no leak" and
  "allocator never returned memory". It also does not cover weeks (only the
  measured window), an isolated stack (both share the host, so a machine-level
  effect moves both series — that is why they run concurrently and why `load1`
  is logged every sample), guaranteed equal *achieved* volume (the recipe is
  identical and the churn rate is fixed, and achieved volume is recorded per
  side), or any proxy type other than one TCP proxy.

Keep `SOAK_CHURN_RATE` modest: each closed connection parks sockets in
TIME_WAIT (~30 s on macOS, 16 384-port ephemeral range), so the per-sample
`time_wait` count is the check that a run is not drifting into port exhaustion.

All are host-specific like the throughput baseline — compare only against
same-host runs. Regenerate commands:

```bash
bash scripts/latency-baseline.sh
bash scripts/memory-baseline.sh
# duration_s interval_s — a real soak wants hours; the short form just validates
bash scripts/rss-soak.sh 10800 45
# a throwaway validation run, so a live soak's artifact is not clobbered:
SOAK_OUT=/tmp/rss-soak-validation.jsonl bash scripts/rss-soak.sh 180 30
```

Only one soak runs at a time (lock file `/tmp/rss-soak.lock`); a validation run
is refused while a real soak is live rather than allowed to steal its ports or
overwrite its artifact. Start a long run detached so it survives the shell:

```bash
nohup bash scripts/rss-soak.sh 10800 45 > /tmp/rss-soak.log 2>&1 &
```

## Regenerate

```bash
# duration_s streams (short values just validate; use 10+ for a real baseline)
bash scripts/throughput-baseline.sh 10 1
```

Each row must report a positive `mbps`. A `0.0` row means that config's frpc
failed to connect — check the frps/frpc TLS or transport keys before trusting
the file.
