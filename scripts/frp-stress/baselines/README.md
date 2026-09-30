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
| `meta` | one first line: host, platform, cores, frp-rs version + git sha (with `frp_rs_dirty` covering the soak script, its helpers AND the `scripts/frp-stress` generator sources, `harness_sha256` for each of those parts plus `frp_stress_tree`, and `rs_bin_source` saying whether the measured frp-rs binaries were built here or supplied via `FRPS_BIN`/`FRPC_BIN`), Go frp version + dir, the four binary `sha256` values, the traffic recipe, the ports, the resolved run dir, the RSS ceiling the run was produced under (`rss_ceiling_kb`), and an explicit `caveats` list. Every string field — the run dir, the binary paths, the host name — is JSON-escaped by the writer, so a `"` or `\` in a path cannot make the line unparseable (an unparseable `meta` line is skipped by the reader, which used to drop the digests, the ports and the same-binary guard from a run that still said "run completed") |
| `sample` | one per interval: `elapsed_s`, UTC `ts`, `load1`, the host-wide `time_wait` socket count, and RSS in KB for all four processes (`null` when the reading was unusable — see below) |
| `summary` | one last line: per-process `first`/`last`/`min`/`max`/`mean`/`first_hour_mean`/`last_hour_mean`/`growth_pct_first_to_last`, a computed `trend` per process (least-squares `slope_kb_per_hour`, first/last-quarter means, `monotonic_nondecreasing`), achieved `traffic` per side (including `failed_streams`), `achieved_equality` between the two sides, load and TIME_WAIT ranges, the ceiling the verdict was computed under (`rss_ceiling_kb` and `rss_ceiling_source`), and `aborted` |

**An artifact with no trailing `summary` line is an incomplete run.** That is a
convention the reader of a series applies, not something the script can test
for, because a run killed with `kill -9` never reaches the summary at all. When
the summary *is* written, `aborted` is `null` only for a completed window;
otherwise it names every fault found and `scripts/rss-soak.sh` exits 3. A
pre-flight failure (no usable bridge) instead exits 1 and writes no artifact.
The faults are:

- a process that died at any point in the window, **including during the last
  sampling interval** (the liveness scan runs before the window-end test);
- any RSS column with zero usable readings — `ps` never returned a number for it;
- an RSS reading outside `1..SOAK_RSS_CEILING_KB` (default 100 GiB), or a column
  whose readings are **all identical** across the series. Either shape can only
  come from `ps` not reporting real processes: a stubbed `ps` printing `0`
  produced a table of zeros, and one printing a constant produced exactly the
  "perfectly flat" line this artifact is meant to test for. The identical-values
  rule is deliberately strict — real RSS over hours always moves, so a
  legitimately flat short validation is a cheap re-run, whereas a constant is
  otherwise indistinguishable from the strongest possible result;
- either side's churn completing no echo round trips, or its steady stream
  moving no bytes;
- either side's totals below the absolute floor (10 churn round trips, 1 MiB of
  steady traffic) — a run that moved almost nothing measured almost nothing,
  even though it did measure it;
- either side's steady path reporting `failed_streams > 0` (a torn-down path);
- the recorded `bin_sha256` showing the frp-rs and Go binaries of a pair to be
  the same file — one implementation run on both sides is not a comparison (the
  soak refuses this before the window opens too);
- the two sides' achieved volume differing by more than `SOAK_TRAFFIC_TOLERANCE`
  (default `0.10`) — both are handed the same paced recipe, so a large gap means
  the comparison is not head-to-head. The value must be a finite number in
  `(0, 1]`: `nan` compares false against everything and used to disable the
  check while the run still reported `"aborted": null`.

A missing reading prints `-`, never a fabricated `0`, and a column with no
readings at all prints `NO READINGS`. `scripts/tests/rss-soak-run-dir.sh` (run
by the `health` CI job, no network or built binary needed) drives the real
run-dir helpers and the real summary reader over these cases, including the
stubbed-`ps` shapes above; it enforces a floor on its own check count so that
deleting a case cannot silently pass.

Two env knobs tune the refusals above, and both are documented by
`bash scripts/rss-soak.sh --help` along with the rest:

- `SOAK_TRAFFIC_TOLERANCE` (default `0.10`) — relative achieved-volume spread
  allowed between the two sides.
- `SOAK_RSS_CEILING_KB` (default `104857600`) — largest RSS reading accepted as
  real; the bound is applied by the soak when it samples and again by the
  summary reader, so an artifact produced elsewhere cannot present an
  implausible value as evidence either.

### The RSS ceiling

`SOAK_RSS_CEILING_KB` is a **plausibility bound**, not a measurement of what the
processes do: a reading outside it is recorded as a missing reading, never
published. The run writes the bound it used into the artifact as
`rss_ceiling_kb`, and the summary reader prefers **the artifact's own recorded
ceiling** over the ambient `SOAK_RSS_CEILING_KB`. The verdict is then a property
of the artifact rather than of the environment that reads it: before this, the
same file read `"aborted": null` under one setting and
`rc 3, "implausible RSS reading(s) ignored"` under another. The environment (and
then the compiled-in default) is only the fallback for an artifact that records
no ceiling of its own — an older or hand-written series.

The fallback default is **1 GiB (`1048576` KB)**, down from 100 GiB. It comes
from the committed baselines: `memory-Mac.jsonl` records
`rss_kb_frps`/`rss_kb_frpc` of 17328/16176 KB (idle, plain), 29776/28880 KB
(idle, encrypt), 17424/15440 KB (churn, plain) and 27312/17728 KB (churn,
encrypt) — a 15.4-29.8 MB band, so 1 GiB still leaves roughly 35x headroom for a
heavier workload or a longer window. The old default was wide enough to accept a
fabricated ~99.2 GiB column while real readings are tens of MB, and a still
wider setting (`SOAK_RSS_CEILING_KB=1000000000000`) accepted a ~84 TiB band. The
knob remains settable, but a raised bound is now recorded in the artifact and
echoed by the summary (`rss_ceiling_kb` plus `rss_ceiling_source`), so a vacuous
bound is visible instead of silent. Being a magnitude bound, the ceiling cannot
by itself distinguish a real series from a fabricated one whose values are
plausible.

A verdict already recorded in an artifact is **monotonic**: the reader appends a
`summary` line and refuses to clear an earlier `aborted`, so re-reading or
re-running the summary over a series that already aborted keeps the death
verdict (`a previous summary already aborted this artifact …`).

What the series does and does not establish:

- **Does**: how each implementation's resident memory moves over hours on one
  host under identical *offered* load, sampled side by side.
- **Does not**: prove absence of leaks. RSS is not live heap — it includes
  allocator retention, page-fault and page-cache effects, and memory the OS has
  not reclaimed, so a flat line is consistent with both "no leak" and
  "allocator never returned memory". It also does not cover weeks (only the
  measured window), an isolated stack (both share the host, so a machine-level
  effect moves both series — that is why they run concurrently and why `load1`
  is logged every sample), exactly equal *achieved* volume (the recipe is
  identical and the churn rate is fixed, but pacing is applied to combined
  sent+received bytes and each side's achieved volume is recorded and compared —
  a spread beyond `SOAK_TRAFFIC_TOLERANCE` aborts the run), or any proxy type
  other than one TCP proxy.

`SOAK_STREAM_MBPS` is a MiB/s ceiling on **combined** traffic (sent plus
received) per stream, so the default `5` moves roughly 2.5 MiB/s of payload in
each direction; the unpaced default (`0`) is what the throughput baseline uses.

Keep `SOAK_CHURN_RATE` modest: each closed connection parks sockets in TIME_WAIT
(~30 s on macOS, 16 384-port ephemeral range), so the per-sample `time_wait`
count is the host-level check that a run is not drifting into port exhaustion.
It is counted host-wide and is not attributable to one stack, so read it as a
property of the run rather than as a difference between the two sides.

The run directory defaults to `/tmp/rss-soak` for every run, and the soak clears
its own traffic rows and artifact there after pre-flight and before the window
opens. Without that clear, a generator dying early would leave the previous
run's row for the summary to publish as this run's load — which is exactly the
kind of borrowed evidence the fixture above pins down.

All are host-specific like the throughput baseline — compare only against
same-host runs. Regenerate commands:

```bash
bash scripts/latency-baseline.sh
bash scripts/memory-baseline.sh
# duration_s interval_s — a real soak wants hours; the short form just validates
bash scripts/rss-soak.sh 10800 45
# a throwaway validation run: its own artifact, run dir, lock and ports, so a
# live soak is neither disturbed nor clobbered
SOAK_OUT=/tmp/rss-soak-validation.jsonl SOAK_RUN_DIR=/tmp/rss-soak-validation \
  SOAK_LOCK=/tmp/rss-soak-validation.lock \
  SOAK_RS_CONTROL=18300 SOAK_RS_REMOTE=18301 SOAK_RS_ECHO=18302 \
  SOAK_GO_CONTROL=18400 SOAK_GO_REMOTE=18401 SOAK_GO_ECHO=18402 \
  bash scripts/rss-soak.sh 180 30
```

Only one soak runs at a time (lock file `/tmp/rss-soak.lock`, override with
`SOAK_LOCK`); a validation run is refused while a real soak is live rather than
allowed to steal its ports or overwrite its artifact. Start a long run detached
so it survives the shell — SIGTERM stops it promptly, and a `kill -9` still
leaves no orphans because a watchdog reaps the children when the script dies:

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
