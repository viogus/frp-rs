# Bridge buffer size: the knob did not reach the yamux frame

**Date:** 2026-11-08. **Host:** macOS arm64 (Apple M2), rustc 1.98.1, load
average 6-9 during the runs (busy laptop; interleaved A/B, every pair
same-window). **Base:** `602910a5`.

## 1. Symptom

`FRP_BRIDGE_BUF_KB` sizes the bridge copy buffer, and `frp-core/src/mux.rs`
configures yamux — but the *frame* size was a hardcoded `32 * 1024`, so
raising the knob only changed how many bytes went into each frame, never how
many frames carried them. In the 2x2 from
[`2026-11-08-mux-throughput-scaling.md`](2026-11-08-mux-throughput-scaling.md)
§5 that is arm **B** (64 KiB buffer / 32 KiB frames): statistically level with
the shipped 32/32 default.

The knob therefore documented a tuning axis that could not move the thing it
was named after.

## 2. Cause

`frp-core/src/mux.rs:484`:

```rust
cfg.set_split_send_size(32 * 1024);
```

The bridge hands yamux one chunk per write (`copy_pooled`, chunk =
`buffer_pool::BUFFER_SIZE`). With `split_send_size` fixed at 32 KiB, a 64 KiB
chunk was cut into two frames no matter what the knob said — two headers, two
window-credit checks, two waker hand-offs.

## 3. Fix

One line: derive the split from the same value the chunk is cut at.

```rust
cfg.set_split_send_size(*crate::buffer_pool::BUFFER_SIZE);
```

Safe at every value the knob accepts (4 KiB-1 MiB): the sender takes
`min(stream window, split_send_size)`, so a frame can never exceed the peer's
advertised window, and Go's hashicorp yamux splits only at its own window
boundary — it has no small-frame assumption. `set_split_send_size` does no
validation of its own (`vendor/yamux/src/lib.rs:254-256`), which is why the
knob's 4 KiB floor is what keeps a zero out.

**The default does not change** (32 KiB). See §6.

## 4. Result — one binary, only the knob differs

`FRP_BRIDGE_BUF_KB=64` below; unset means the 32 KiB default. Strict ping-pong
throughput (`scripts/frp-stress --scenario throughput`, MiB/s), mux on:

| streams | duration | 32 KiB (default) | 64 KiB | delta |
|---|---|---|---|---|
| 1 | 10 s | 289.04 | 313.19 | +8.4% |
| 4 | 12 s | 471.64 / 478.34 / 475.62 | 540.24 / 563.15 / 557.41 | **+16.5%** (means 475.2 -> 553.6) |
| 8 | 10 s | 538.55 | 621.15 | +15.3% |

CPU-seconds for the 12 s window, frps+frpc: 26.94/27.42/27.40 at 32 KiB versus
24.26/24.67/24.64 at 64 KiB — **about 10% less CPU per byte moved**, the same
direction as the 2x2.

Plain (no mux) 4 streams, 12 s: 759.04 / 762.92 versus 784.00 / 784.33
(+3.0%, CPU 36.3 s -> 31.1 s). So the knob is worth having outside mux too;
mux is where the frame match pays.

Latency (`--scenario latency --mode steady`, 1500 samples, 64-byte messages):
p50 219.1 us at 32 KiB versus 218.1 us at 64 KiB — unchanged. Setup p99
(one pair) moved 1064 us -> 2326 us, which is not attributable on a host at
load average 8 (the same scenario's setup p99 has swung by 2x between runs of
the *same* binary in this session).

## 5. What it costs

Per bridge the plain path holds one buffer per direction: 2 x 32 KiB at the
default, 2 x 64 KiB when raised. The pool ceiling also doubles in bytes at the
same `FRP_BRIDGE_POOL_MAX` (128 x 32 KiB = 4 MiB versus 8 MiB).

Measured, and honestly inconclusive:

- 4-stream load, peak RSS: +0.5 MB per process at 64 KiB (frps 11.5 -> 12.0 MB,
  frpc 10.8 -> 11.4 MB).
- 200 idle bridged connections, RSS delta from a warm idle baseline: 32 KiB
  +12.3 MB (frps) / +9.5 MB (frpc); 64 KiB +9.0 MB / +6.4 MB. The order is
  backwards versus the theoretical 2x, which means the measurement is dominated
  by pool state and lazy allocation, not by the buffer size. Nothing here
  establishes a per-connection cost, and nothing here disproves one.

## 6. Why the default stays at 32 KiB

Go frp copies with a 32 KiB `io.Copy` buffer, and `docs/architecture.md`
records that this default was deliberately halved from 64 KiB for
per-connection footprint. Flipping it is a footprint decision for every
deployment, including the high-fan-out servers `docs/deployment.md` calls out,
and §5 cannot bound that cost.

What would flip it: a fan-out memory baseline (the `scripts/memory-baseline.sh`
axis) at a few hundred to a thousand concurrent bridges, showing the extra
32 KiB per direction per bridge against the +15% mux throughput. Until then the
win is an operator choice with a documented number behind it, not a new
default.

## 7. Verification

- `cargo test --workspace --all-features`: all suites pass except
  `dashboard_integration::test_dashboard_proxy_traffic_live`, which fails on
  the unmodified base tree too (pre-existing, HTTP "early eof").
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: no
  issues. `cargo fmt --all -- --check`: clean.
- Cross-compat against Go frp v0.72.0 passes both directions, including with
  the knob at 64 KiB (so 64 KiB yamux frames interop):
  `go-to-rust-mux-plain`, `rust-to-go-mux-plain`, `rust-to-go-mux-tls`,
  `go-to-rust-mux-encrypted`, `rust-to-go-mux-encrypted`, `go-to-rust-mux-tls`,
  `go-to-rust-kcp-mux`, `rust-to-go-kcp-mux`, `go-to-rust-wss-mux`,
  `go-to-rust-tcpmux`, `rust-to-go-tcpmux`.
- `frp-core/src/udp_binary.rs` gained `TAKE_PAYLOAD_THRESHOLD` (32 KiB) in the
  same change: its copy-or-take decision used to key off `BUFFER_SIZE`, so a
  raised buffer would have made the zero-copy path unreachable (no legal UDP
  payload exceeds 65507 bytes). Decoupling keeps the codec's allocation
  strategy independent of a transport knob.
