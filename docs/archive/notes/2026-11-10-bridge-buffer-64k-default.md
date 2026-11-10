# The bridge buffer is 64 KiB by default (32 KiB on macOS)

**Date:** 2026-11-10 · **Status:** shipped · **Scope:** `frp-core/src/buffer_pool.rs`,
`frp-core/src/mux.rs` (unchanged derivation), `FRP_BRIDGE_BUF_KB` semantics

`BUFFER_SIZE` is not just a copy buffer: it is the yamux data-frame payload,
because `mux.rs` derives `split_send_size` from it. At 32 KiB a 64 KiB bridge
chunk therefore travels as two frames — two 12-byte headers, two window-credit
checks, two waker hand-offs. At 64 KiB it travels as one. The split is capped at
64 KiB in any case, so 64 KiB is the largest default that buys anything.

## 1. Why the default moved

The earlier record (`2026-11-10-mux-frame-cost.md`) measured the knob on a
4-vCPU Linux **container** at +12% and kept the default at 32 KiB, because
`FRP_BRIDGE_BUF_KB=64` costs the macOS non-mux WebSocket rows ~40–45%. Re-running
the comparison on a dedicated Linux VM with more repeats, the gain is larger and
much tighter than the container suggested, and the loss does not reproduce on
Linux at all. So the default follows the platform: 64 KiB where it helps,
32 KiB on macOS where it hurts.

## 2. Method

The harness and both binary sets live **outside the tree**, in
`/Users/cdf/kcpbench` (`ab2.sh`, `res2.sh`, `bench-linux`, `abbench`, and the
`base-bin/` + `def64-bin/` builds); the VM copies are in `/root/bench`.

`ab2.sh <bindir> <label> <flows> <mux> <server-extra> <client-extra>` on the
host described in `2026-11-10-real-host-throughput.md` §2 (4 vCPU EPYC-Milan,
steal 0.0%, Debian 13, kernel 6.12). One binary — the release build of the commit
under test — with only `FRP_BRIDGE_BUF_KB` differing between the two arms.
Payload `abbench stream`, 8192 MiB per run, 4 flows unless stated, alternating
A/B, mean of the stated number of pairs. `ws` rows use
`transport.protocol = "websocket"` on the client.

## 3. Result on Linux

| workload | 32 KiB | 64 KiB | change |
|---|---|---|---|
| `tcpMux` + TLS, 4 flows, 5 pairs | 523.4 / 522.4 / 537.3 / 523.3 / 523.6 (mean 526.0) | 575.5 / 605.5 / 593.2 / 602.6 / 608.2 (mean **597.0**) | **+13.5%** |
| `tcpMux` + TLS, 1 flow, 2 pairs | 505.6 / 511.1 (508.4) | 572.4 / 574.5 (573.5) | **+12.8%** |
| WebSocket, no mux, 4 flows, 3 pairs | 1059.2 / 1104.3 / 1029.0 (1064.2) | 1183.1 / 1207.9 / 1246.6 (1212.5) | **+13.9%** |
| no mux + TLS, 4 flows, 2 pairs | 1143.3 / 1225.3 (1184.3) | 1228.4 / 1162.7 (1195.6) | +1.0% (noise) |
| no mux, no TLS, 4 flows, 2 pairs | 2098.6 / 2329.5 (2214.1) | 2218.7 / 2150.4 (2184.6) | −1.3% (noise) |

Every `tcpMux` pair moved the same way: +9.9%, +15.9%, +10.4%, +15.1%, +16.2%.
The plain rows are untouched, which is the expected control — without `tcpMux`
there are no frames to consolidate.

Resource cost and benefit, same host, `tcpMux` + TLS, 2 reps (`res2.sh` samples
`/proc/<pid>/stat` and `VmHWM` around the run):

| | throughput | CPU per MiB (frps+frpc) | peak RSS frps/frpc |
|---|---|---|---|
| frp-rs, 64 KiB | 558.3 MiB/s | **3,723 µs** | 16.0 / 15.4 MB |
| frp-rs, 32 KiB | 481.1 MiB/s | 4,311 µs | 13.0 / 16.1 MB |
| Go frp v0.72.0 | 386.0 MiB/s | 5,184 µs | 34.8 / 49.9 MB |

So the default is not a CPU/memory trade: it removes work (one frame per chunk
instead of two) and costs 2×64 KiB of buffer per live bridge instead of
2×32 KiB — about 2 MB of RSS at the measured fan-out, versus 12 µs per frame
saved.

## 4. Why macOS keeps 64 KiB too

The first version of this change shipped a macOS carve-out (32 KiB there), on
the strength of `scripts/protocol-matrix.sh` reporting macOS `ws` rows 40-45%
slower at 64 KiB: `ws` 301.5 -> 165.5 MiB/s, `wss` 226.2 -> 134.0, `ws`+TLS
222.75 -> 133.2, while `ws`+TLS+mux moved only 185.8 -> 181.2 and `tcp`+TLS+mux
went 288.8 -> 312.9 the other way.

**That row does not measure throughput.** `protocol-matrix.sh` runs
`frp-stress --scenario throughput --streams 1`, which is a strict ping-pong: one
64 KiB write, then a 64 KiB read, repeated. Nothing overlaps, so the number is
frame-granularity *latency*, and the buffer size that wins depends on how the
chunks line up with the message — not on how fast bytes move. Re-measured with
the same harness on both platforms, same binary, knob as the only difference:

| shape | macOS arm64 | Linux VM |
|---|---|---|
| 1-stream 64 KiB ping-pong, 64 KiB buffer | 165 MiB/s | 191-197 |
| 1-stream 64 KiB ping-pong, 32 KiB buffer | **301** | **10-30** |
| 8 KiB ping-pong, 32 vs 64 KiB buffer | 73.5 vs 73.9 (no difference) | — |
| 32 KiB ping-pong, 32 vs 64 KiB buffer | 193.6 vs 194.4 (no difference) | — |

The pathology needs the buffer to be **as large as the message** (64 KiB chunk,
64 KiB buffer) — and then it hits whichever side the chunking does not pipeline
on: macOS at 64 KiB, Linux at 32 KiB, by 2x and 10-20x respectively. With an
8 KiB or 32 KiB message both sizes measure the same. So the row measures the
harness, and using it to pick a default would have been choosing a platform
kernel's ping-pong behaviour.

**The streaming shape disagrees decisively.** One-way transfers (the shape a
proxy is actually asked to move), macOS arm64, `abbench stream`, three
independent runs per cell:

| shape | 32 KiB | 64 KiB |
|---|---|---|
| `ws`, no mux, 1 flow | 1,340 / 1,461 / 1,557 / 1,558 | **2,248 / 2,297 / 2,303 / 2,313** (+48%) |
| `ws`, no mux, 4 flows | 1,684 / 1,774 / 1,852 / 1,862 | **2,362 / 2,376 / 2,390 / 2,390** (+27-42%) |
| `ws` + `tcpMux`, 4 flows | 704 / 709 / 730 / 735 | **1,107 / 1,139 / 1,183** (+55%) |
| `tcp`, 1 flow | 458 / 468 | 458 / 464 (no difference) |

macOS therefore keeps 64 KiB, and `DEFAULT_BUFFER_SIZE` is a single constant.
The lesson is recorded here rather than in the matrix README because the matrix
is still the right gate for "does data move on this transport" — it is the wrong
instrument for "how fast", and it was used as one.

## 5. What ships

- `DEFAULT_BUFFER_SIZE` = 64 KiB, the same on every platform (§4).
- `FRP_BRIDGE_BUF_KB` (4–1024) still wins; out-of-range values fall back to the
  platform default (`resolve_buffer_size` is a pure function with tests).
- `MAX_POOLED_BUFFERS` (128) is unchanged, so the pool ceiling becomes 8 MiB of
  64 KiB buffers; the pool only holds buffers that were used and released, so an
  idle process keeps none of it.
- Docs updated: `docs/architecture.md` (bridge buffer bullet),
  `docs/deployment.md` (the knob paragraph), `CHANGELOG.md`, `README.md`
  (Performance section — the shipping row is now +41%, not +23%).

## 6. Against Go, with the new default

Same host, same session, 3 interleaved reps per row (means):

| configuration | frp-rs | Go frp v0.72.0 | frp-rs lead |
|---|---|---|---|
| `tcpMux` + TLS | 561.9 | 399.2 | **+41%** |
| `tcpMux`, no TLS | 970.1 | 646.9 | **+50%** |
| no `tcpMux`, TLS | 1298.1 | 955.6 | **+36%** |
| no `tcpMux`, no TLS | 2167.5 | 1649.5 | **+31%** |

Go is unchanged by this work; its own rows do not use frp-rs's buffer.

## 7. Limits

- One host, one network path (loopback in a VM whose own host is containerised).
- Four flows on four vCPUs is a CPU-bound regime; a host with idle cores can
  reorder the cross-implementation comparison (see
  `2026-11-10-real-host-throughput.md` §8).
- The macOS *streaming* numbers above are from `abbench stream` on one laptop,
  four runs per cell, alternating; the ping-pong numbers are the matrix harness.
  Neither is a CI measurement.
- The 64 KiB frame is legal for every peer: `fatedier/yamux v0.3.0` writes
  `min(window, len)` with no small-frame constant, and KCP/QUIC/WS accept it —
  the WebSocket reader's cap is 65664 bytes, 116 more than a 64 KiB frame plus
  its 12-byte header (65548 used).

## 8. Reproduce

```bash
# same binary, knob only — alternate A/B, 5 pairs
for i in 1 2 3 4 5; do
  FRP_BRIDGE_BUF_KB=32 bash ab2.sh <bin>/ "" 4 true "" ""
  FRP_BRIDGE_BUF_KB=64 bash ab2.sh <bin>/ "" 4 true "" ""
done

# resources
bash res2.sh <bin>/ rs-64k 4 true "" ""

# via the matrix, on macOS (this is where the WebSocket cost shows)
FRP_BRIDGE_BUF_KB=64 bash scripts/protocol-matrix.sh
```
