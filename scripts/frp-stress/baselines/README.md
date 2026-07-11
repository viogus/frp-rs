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

## Regenerate

```bash
# duration_s streams (short values just validate; use 10+ for a real baseline)
bash scripts/throughput-baseline.sh 10 1
```

Each row must report a positive `mbps`. A `0.0` row means that config's frpc
failed to connect — check the frps/frpc TLS or transport keys before trusting
the file.
