# UDP throughput: the client's buffer-reuse gate cost 8.7x

**Status:** fixed (client work-conn reply path). **Host:** Apple M2 / macOS arm64,
8 cores, rustc 1.98.1. **Reference:** Go frp v0.72.0 (`scripts/download-go-frp.sh`).

## 1. Symptom

A strict ping-pong UDP load through frps + frpc (`scripts/frp-stress --scenario
udp`, 4 flows, 1 KiB datagrams) measured **919 pps** for the Rust client where the
Go client on the identical server and config measured **10,126 pps**. The server
side was not the problem, and neither was the transport — a mixed-binary matrix
at 512 B / 4 flows isolated it to one process:

| frps | frpc | pps |
|---|---|---|
| rust | rust | 1,009 |
| go | rust | **919** |
| rust | go | 7,979 |
| go | go | 10,126 |

Direct harness -> echo with no proxy at all: 55,764 pps (72 us RTT), so the whole
gap was inside the proxy path, and the client was the worse half.

## 2. The stall was a timer, not a syscall

Per-datagram latency through the proxy was ~4 ms, and it depended on the reply
size: 512 B -> 3.49 ms, 8000 B -> 0.33 ms. Probing the client's session task with
timestamps around each stage (`P1` = reply received from the local service,
`P4` = payload handed to the writer task):

```
P0 474990  (local echo sent)
P1 475191  local round trip              201 us
P4 477769  <- 2,578 us spent between P1 and P4
P2 477838  writer dequeued                 69 us
P3 477897  frame written + flushed         59 us
```

So ~2.6 ms was burned inside `run_udp_session`, between reading the datagram and
handing it to the writer — nowhere near the work conn, yamux, or the server.

## 3. Root cause

`frp-client/src/work_conn/udp.rs`, in `run_udp_session` (pre-fix):

```rust
let payload = match ret_rx.try_recv() {
    Ok(mut spare) if spare.capacity() >= udp_packet_size.max(1) => { ... }
    _ => match tokio::time::timeout(UDP_SPARE_RETURN_WAIT, ret_rx.recv()).await {
        Ok(Some(mut spare)) if spare.capacity() >= udp_packet_size.max(1) => { ... }
        _ => buf[..n].to_vec(),
    },
};
```

`udp_packet_size` defaults to **1500** (`frp-core/src/config/client.rs`, from
`transport.udpPacketSize`). The alloc fallback `buf[..n].to_vec()` produces a
buffer of capacity `n` — for a 512-byte datagram, 512. That buffer is written,
handed back to `ret_rx`, and then **rejected by the same gate that produced it**,
because `512 < 1500`. Every datagram therefore re-entered the
`UDP_SPARE_RETURN_WAIT = 1 ms` branch, which measured as ~2.6 ms once timer
rounding and scheduling are counted. Reuse never happened at all: the "spare"
path was reachable only for buffers that were already at least as large as the
configured recv window.

The config workaround confirmed the mechanism before any code changed: setting
`transport.udpPacketSize = 512` (so the gate accepted the 512-byte buffers)
raised the same client from **914 to 7,927 pps** — 8.7x, purely from a config
value that made an internal check pass.

## 4. Fix

`reuse_spare(spare, src, min_cap)` grows an undersized hand-back once
(`Vec::with_capacity(min_cap)`, `min_cap = udp_packet_size.max(n)`) instead of
rejecting it, and the alloc fallback now also allocates at the full window, so
the buffer it hands back satisfies the fast path from the second datagram on.
The bounded wait stays, now only reachable when the writer genuinely has not
returned a buffer yet.

## 5. Result

Go frps (isolates the client), 4 flows, 6 s:

| datagrams | before | after |
|---|---|---|
| 512 B | 773 | **7,916** |
| 512 B, `udpPacketSize = 512` (workaround) | 7,927 | 7,894 |
| 1024 B | 1,358 | **6,523** |
| 1500 B | — | **7,541** |
| 8000 B | — | **7,609** |
| 512 B, 8 flows | — | **8,784** |

With a Rust frps as well: 6,941 pps at 512 B — the server side costs ~12% on top.

## 6. What is left

~20-30% behind the Go client at the same server (7.9k vs 10.1k pps) once the
timer is gone. That residual is a different question: it is per-datagram work
inside the session task (shard lookup, mpsc hop, one syscall pair), not a
fixed delay, and it is the next candidate rather than an open bug.

## 7. Reproduce

```bash
cargo build --release -p frps -p frpc
cargo build --release --manifest-path scripts/frp-stress/Cargo.toml
# frps on 18920, frpc serverPort 18920 with one `type = "udp"` proxy
# localPort 18921 -> remotePort 18922, echo backend on 18921:
./scripts/frp-stress/target/release/frp-stress --scenario udp-echo --port 18921 &
./scripts/frp-stress/target/release/frp-stress --scenario udp --port 18922 \
  --streams 4 --duration 6 --udp-packet-size 512 --label after
```

`/tmp/udp-mix.sh <rs|go> <rs|go> <pkt> <flows> <secs> <label>` automates the
mixed-binary variant (env `FRPS_BIN`, `FRPC_BIN`, `UDP_BUFSIZE`); it needs the
echo port free, so it kills any stale `udp-echo`/`udp_echo2` holder first.
