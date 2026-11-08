# Inline yamux writes: removing the connection-driver round trip

Status: experiment, `exp/yamux-inline-write`. Nothing here is landed.

## 1. What we are chasing

Under `tcpMux` the frp-rs UDP data plane costs roughly **twice** the CPU per
datagram of the same proxy without mux, and throughput at 4 flows drops from
13,388 pps to 6,781 pps (512 B datagrams, one core-bound client, Go frps to
isolate the client):

| path | 1 flow µs/pkt | 4 flows µs/pkt | 4 flows pps |
|---|---|---|---|
| frp-rs, no mux | 57 / 56 | 52 / 54 | 13,388 |
| frp-rs, mux | 118 / 119 | 135 / 138 | 6,781 |

Go shows the same shape (116 → 148 µs, 10,126 → 9,695 pps), so a mux tax is
normal — the question here is only whether frp-rs pays more than it must.

## 2. Where the time goes (measured)

Two independent measurements, both on one 512 B datagram through a Go frps:

**a. A minimal yamux ping-pong** (`frp-core/examples/yamux_pp.rs`, two tasks,
one stream, loopback TCP): raw TCP 39.96 µs/msg, yamux 64.46 µs/msg — yamux's
own floor is **24.5 µs/msg**.

**b. The real client path**, instrumented with `eprintln` timestamps
(`P1` session recv → `P4` session → writer-channel send → `P2` writer recv →
`YW` frame queued in yamux → `P3` write+flush returned → `DW` driver dequeued
→ `DS` driver `start_send` → `YF` socket flush complete):

| segment | median |
|---|---|
| `P1→P4` session bookkeeping | 14 µs |
| `P4→P2` session → writer task hop | 14 µs |
| `P2→YW` encode + yamux stream write | 15 µs |
| `YW→P3` | 6 µs |
| `P3→DW` → `DW→DS` driver wake + encode | 10 + 7 µs |
| `DS→YF` driver flush | 25 µs |
| `YF→P1` network + peer | 215 µs |

The probe build inflates absolutes (≈6 × `eprintln` per datagram); the
uninstrumented segment `P3→YF` measured **29 µs**. That is the cost this
experiment targets: the frame is queued by the writer task and the connection
driver — a different task — has to be woken, dequeue, encode and flush it.

Not the cause (both falsified earlier, see
`2026-11-08-mux-throughput-scaling.md` and `2026-11-08-udp-spare-reuse.md`):
bridge buffer size, yamux frame count (`split_send_size`), header/payload
coalescing (`DS→F1` is unchanged and pps moved 3,327 → 3,474 across three
interleaved pairs, i.e. inside noise).

## 3. Why it cannot be fixed from frp's side alone

`Connection<T>` owns the socket (`vendor/yamux/src/connection.rs`,
`Active::poll` → `self.socket.start_send_unpin(frame)` + `poll_flush_unpin`) and
is poll-driven by frp's mux driver (`frp-core/src/mux.rs:759`,
`poll_fn(|cx| conn.poll_next_inbound(cx))`). `Stream::poll_write` therefore
cannot write: it copies the body into a pooled buffer and hands a
`StreamCommand::SendFrame` to that driver over an mpsc
(`vendor/yamux/src/connection/stream.rs:408-440`). Go's fatedier fork has the
same channel design, which is why it pays a similar tax — but its goroutine
wake is cheaper than a task wake plus a full driver poll.

## 4. Design

Split the connection's I/O by direction so the owner of a stream can write
without owning the driver:

1. `Connection::new_split(read, write)` — the driver keeps the read half and
   everything that must stay serialized with reads (window updates, pings,
   `GoAway`, stream state). The write half moves behind
   `Arc<Mutex<WriterState>>`.
2. `WriterState` holds the write half, the frame-pool bookkeeping and a small
   FIFO of control frames (pong, window update, RST, `GoAway`) that the driver
   queues. `Stream::poll_write` does `try_lock`, drains any queued control
   frame first (control stays privileged, as in Go), then encodes and writes
   the data frame **inline**; if the lock is contended it falls back to the
   existing mpsc path, so behaviour is never worse than today.
3. The driver's own writes go through the same lock, so frame atomicity is
   unchanged: exactly one writer at a time.
4. `frp-core/src/mux.rs` splits the socket (`tokio::io::split`) before
   `.compat()` and calls `new_split`. Both call sites (`:751` server,
   `:971-972` client) change together.

Expected effect: `P3→YF` (29 µs) collapses into `P2→YW`, i.e. the client-side
per-datagram cost drops from ~78 µs to ~50 µs, roughly **+25-30% pps under
mux** (6.8k → ~8.5-9k at 4 flows), which would put frp-rs level with or ahead
of Go's 9.7k while keeping its cheaper per-datagram CPU.

## 5. Risks and gates

- **Blast radius**: `tcp-mux` is default-on, so every TCP proxy rides this
  code. Frame atomicity and control-frame ordering are the two invariants that
  must not break; both are covered by the vendor tests (`rst`, `ack_timing`,
  `window_update`, `close`) plus `scripts/compat-test.sh` (86 scenarios) and
  `scripts/protocol-matrix.sh` (11 transport rows).
- **Lock contention**: with many streams writing at once the `try_lock`
  fallback keeps the current behaviour; a contended lock must never block the
  driver's read path (the driver holds the lock only for its own frame).
- **Read/write split**: `tokio::io::split` serializes reads and writes on the
  split halves; that is exactly the guarantee needed here, but it must be
  measured — if the split's internal lock shows up in `P2→YW`, the change is
  not worth it.
- **Vendored crate**: `vendor/yamux` already carries frp-rs patches (body
  pool, RST queue, cancel-safety), so this is the same kind of change the
  vendor directory exists for.

## 6. Plan

1. `new_split` + `WriterState` + inline `poll_write` behind a non-default
   constructor (existing `new` keeps the mpsc path). Build, vendor tests.
2. Measure: UDP 1/4 flows with and without mux, TCP mux throughput, the
   `P3→YF` probe.
3. Gates: vendor tests, `cargo test --workspace --all-features`,
   `scripts/compat-test.sh`, `scripts/protocol-matrix.sh`,
   `scripts/stress-test.sh` (connection churn), then two reviews (one
   adversarial) before any PR.
4. If step 2 shows less than ~10% on the mux rows, stop and record the
   negative result here rather than landing the complexity.
