# The streaming shape, frp-rs against Go frp

2026-11-22. Measurement only — no production code changed.

## Why the shape was missing

`scripts/frp-stress` had one throughput scenario, and it is a ping-pong: the
client writes 64 KiB and then `read_exact`s the echo before writing again. On
that shape the one-flow rate is 320 MiB/s (mean of *two* reps, 313.8 and 326.1,
`docs/archive/notes/2026-11-21-worker-migration-mux.md:39`; the shape's own
stable-mode row reads 165-301 MiB/s at
`docs/archive/notes/2026-11-10-bridge-buffer-64k-default.md:82-85`), while the
same tunnel moving one direction reports over 1 GiB/s. The repo already says
what such a row is worth — "That row does not measure throughput … the number is
frame-granularity *latency*" (`2026-11-10-bridge-buffer-64k-default.md:73-77`)
— so a ping-pong figure is 4-5× below the streaming rate, not a throughput
measurement.

Streaming numbers do exist in the notes (`abbench stream` at
`2026-11-13-splice-wrapper-peel.md:11-12` reports 1320 MiB/s,
`2026-11-10-bridge-buffer-64k-default.md:99-100` another row), but they came
from an ad-hoc tool run by hand: there was no script that ran the streaming
shape against Go frp, and none that recorded what the bytes cost in CPU. Both
are now in the tree.

`frp-stress --scenario stream` (new) with `--scenario sink` (new) closes that:
N connections each `write_all` a 64 KiB payload in a loop until the deadline
and never read back; the peer reads and discards. Bytes are counted once, on
the sender.

## Numbers

macOS arm64, 8 cores, loopback, 10 s, 64 KiB writes, 8 streams unless stated,
MiB/s one direction, 3 reps per cell, the Rust and Go arms alternating within a
rep. Go frp v0.72.0, frp-rs at `main` after #659.

| cell | frp-rs reps (mean) | Go frp reps (mean) | ratio of means | ratio of medians |
|---|---|---|---|---|
| plain tcp, 1 stream | 1567 / 1544 / 1557 (**1556**) | 1252 / 1266 / 1268 (**1262**) | **1.23×** | 1.23× |
| plain tcp, 8 streams | 1315 / 1331 / 1308 (**1318**) | 1212 / 1190 / 1215 (**1205.7**) | **1.09×** | 1.08× |
| `tcp_mux = false` + TLS, 8 | 1673 / 1656 / 1815 (**1714.7**) | 1486 / 1494 / 1474 (**1484.7**) | **1.15×** | 1.13× |
| `tcp_mux = true` + TLS, 8 | 636 / 667 / 650 (**651**) | 750 / 706 / 666 (**707.3**) | **0.92×** | 0.92× |

Raw loopback with no frp in the path — `frp-stress --scenario stream` against
its own `sink`, so the ceiling for the harness itself: 4,774 MiB/s at one
stream, 8,433 / 8,527 / 8,534 at eight. The harness is not the limit in any cell
above.

Read: frp-rs is ahead on every cell except the one where yamux is in the path,
where it is ~8% behind (0.92× on both readings). That is the only measured
deficit on this shape, and it is small enough to be worth confirming before
anything is changed.

## What a second look says

Re-running the same cells later the same day on a host carrying load average
12-28 on 8 cores makes wall-clock MiB/s unusable: it drops by 30%, and the sign
of the mux row moves around (0.92× in the first pass, 1.42× in the validation
run below -- the *same direction* in both cases is "frp-rs is not the slower
one" in only one of them). What survives that kind of noise is CPU time per
byte. The script measures it as `ps -o time=` deltas on frps and frpc across
the cell, expressed as MiB moved per CPU-second:

| cell (8 streams, 10 s) | run | frp-rs MiB/CPU-s | Go frp MiB/CPU-s | ratio |
|---|---|---|---|---|
| `tcp_mux = false` | first, host load 12-18 | 742.6 MiB/s, 17.33 cpu_s → **343** | 896.3 MiB/s, 24.00 cpu_s → 299 | 1.15× |
| `tcp_mux = true` | first | 430.2 MiB/s, 11.57 cpu_s → **297** | 439.4 MiB/s, 19.11 cpu_s → 184 | 1.61× |
| `tcp_mux = false` | validation, 2 interleaved reps | 879.4 / 597.0 → **346 / 265** | 812.4 / 661.0 → 286 / 240 | 1.21× / 1.10× |
| `tcp_mux = true` | validation | 542.0 / 398.3 → **305 / 235** | 381.3 / 367.3 → 177 / 166 | 1.72× / 1.42× |

frp-rs spends less CPU per byte in every cell measured: about 13% less without
mux and 38% less with it in the first pass, 10-28% and 42-72% in the validation
run (whose wall-clock moved 20-40% between reps, which is why the CPU column is
quoted per rep). A tunnel that moves the same bytes for less CPU but fewer
bytes per wall-clock second is waiting, not computing -- which is a property of
this host, not of the framing.

The consequence for the first table: the mux row's "8% behind" is inside what
this machine's own variation produces, so it is recorded as unresolved rather
than as a deficit to chase. Resolving it needs a quiet host or the Linux CI
runner, and the honest summary of the measurement is "frp-rs is not behind on
CPU anywhere, and its wall-clock lead on the mux row is unmeasured".

2. **Where the CPU actually goes.** `sample` on an unstripped build
   (`CARGO_PROFILE_RELEASE_STRIP=false`) during a `tcp_mux = true` + TLS cell:
   the top-of-stack is dominated by parking (`__psynch_cvwait` ~18-19k of ~48k
   samples, i.e. 8 worker threads mostly idle), and the heaviest real work is
   AES (`ring_core_0_17_14__aes_gcm_dec_kernel` 898 samples in frpc, `_enc` 409
   in frps), `memmove` 500, and the socket calls (`__sendto` 1299/2127,
   `__recvfrom` 639/224). There is no single hot frame: the cost is spread
   across the record layer, one copy, and the syscall. Nothing here points at
   an algorithmic bug the way the KCP coalescing work did (a 37% win from
   reading before returning).

## What this does not establish

- The mux row's 0.92× did not reproduce: the validation run of the same cells
  gave 1.42× on the same wall-clock column, and an earlier worker-count probe
  gave 0.93-1.06× on a different shape. On this host the row cannot be
  resolved, so nothing here claims frp-rs is behind on mux -- only that its
  lead there is unmeasured.
- Eight streams on loopback is not a wide area network: window growth, RTT
  sampling and per-frame wake cost all scale differently when the RTT is 30 ms
  rather than 40 µs. A per-frame wake at 10k frames/s is 29 µs of a 64 µs
  budget on loopback (the number `keep/yamux-inline-write-v2` measured) and
  disappears into the RTT on a real link.
- Only `tcp` proxies were measured. The mux path is shared, but UDP proxies
  write one mux frame per datagram, which is the shape where a per-frame wake
  cost is paid most often; that was not measured here.

## If the mux row is confirmed elsewhere

The candidate is the per-frame task hand-off in yamux: a stream hands its frame
to the connection task, which writes it, costing a wake per frame. The
experiment that removes it exists as `keep/yamux-inline-write-v2` (4 commits,
~1,180 lines across `vendor/yamux/src/connection/stream.rs`, `closing.rs` and
`frame/io.rs`): the stream writes its own data frame through the connection's
shared writer, keeps control frames ahead of data frames, and wakes flush
waiters instead of leaving them parked. It was written against the vendored
crate as of 2026-11-09 and rebases with conflicts today, so it would need a
redo rather than a merge. Its stated win is per-datagram latency (UDP proxies),
not bulk streaming, which is another reason to measure the UDP-over-mux shape
before paying for it.

## Reproducing

```bash
cargo build --release -p frps -p frpc
(cd scripts/frp-stress && cargo build --release)
bash scripts/stream-vs-go.sh 3 10 8          # reps, seconds, streams
```

The script prints MiB/s and MiB per CPU-second per arm, interleaves the arms
with the order flipping every rep, and exits non-zero if any arm failed to run
or reported `failed_streams` (a stale frps from an earlier arm is killed and its
port waited on before the next arm, so an arm cannot silently measure the
previous configuration). `GO_FRP_DIR` points at the Go binaries (default
`/tmp/frp_0.72.0_darwin_arm64`, where `scripts/download-go-frp.sh` puts them on
macOS arm64); `FRPS_BIN`/`FRPC_BIN` point at pre-built frp-rs binaries so a
shared `CARGO_TARGET_DIR` build is usable (the harness path is fixed: build
`scripts/frp-stress` in the repo).
