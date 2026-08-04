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

Both are host-specific like the throughput baseline — compare only against
same-host runs. Regenerate commands:

```bash
bash scripts/latency-baseline.sh
bash scripts/memory-baseline.sh
```

## Regenerate

```bash
# duration_s streams (short values just validate; use 10+ for a real baseline)
bash scripts/throughput-baseline.sh 10 1
```

Each row must report a positive `mbps`. A `0.0` row means that config's frpc
failed to connect — check the frps/frpc TLS or transport keys before trusting
the file.
