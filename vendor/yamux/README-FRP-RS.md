# Vendored yamux 0.14.0 (frp-rs)

This directory vendors `yamux` 0.14.0 (crates.io, Parity Technologies)
with five patches, wired in via `[patch.crates-io]` in the workspace
root `Cargo.toml` (`yamux = { path = "vendor/yamux" }`).

## License

Upstream: `Apache-2.0 OR MIT` (see `Cargo.toml` `license` field and the
`LICENSE-APACHE` / `LICENSE-MIT` files copied from
`https://github.com/paritytech/yamux`). This is the same dual license as
upstream; the vendored copy keeps it.

## Patch: per-stream RST on inbound stream-cap hit (instead of GoAway)

Upstream yamux 0.14, when an inbound SYN arrives while the connection is
at `Config::max_num_streams`, answers with `Action::Terminate` — a
GoAway that kills the ENTIRE session (every stream, the control channel
included) (`src/connection.rs`, `on_data` and `on_window_update` SYN
sites). An outbound open at the cap already fails per-open
(`poll_new_outbound` returns `ConnectionError::TooManyStreams`); that
path is unchanged.

frp-rs uses a 1024-stream cap (`frp-core/src/mux.rs` `yamux_config`) as
deliberate DoS hardening, but a cap hit must not take down the session:
frp's control channel and all work connections share one yamux
connection, so a session-killing GoAway would drop every active proxy
for the cost of one hostile open. Go frp's yamux fork (fatedier/yamux,
same semantics as hashicorp yamux v0.1.1) handles the equivalent case
per-stream: on backlog-exceeded inbound SYN it sends a per-stream RST
(`session.go` `incomingStream`: `hdr.encode(typeWindowUpdate, flagRST,
id, 0)` + `sendNoWait`) and the session survives. Go has no concurrent
stream cap at all; the frp-rs cap stays, but the cap-hit response now
matches Go's per-stream reset semantics.

### What changed (src/connection.rs only)

- `Action` gains a `Reset(StreamId)` variant.
- Both inbound-SYN cap sites (`on_data` and `on_window_update`, the
  `self.streams.len() == self.config.max_num_streams` arms) return
  `Action::Reset(stream_id)` instead of `Action::Terminate(...)`.
  The OTHER `Terminate` arms (invalid stream id, duplicate stream,
  bad credit / body) are untouched.
- The `Action` dispatch in `poll` handles `Reset(id)` by queueing a
  Data-typed frame with the `RST` flag for `id` into the dedicated
  `pending_reset_frames` queue — the same frame shape the crate already
  sends when a stream handle is dropped without `poll_close`
  (`on_drop_stream`, `State::Open` arm).
- `pending_reset_frames` is a bounded FIFO `VecDeque` (cap 32,
  `RESET_QUEUE_CAP`) distinct from `pending_read_frame`. A burst of
  cap-hit SYNs while the socket write is backpressured queues one RST
  per stream in FIFO order; at cap the OLDEST pending RST is dropped
  (a reset that can't be sent promptly still ends the stream locally,
  and the peer's lingering entry is bounded by its own session
  timeout). RSTs are idempotent 12-byte headers, so a dropped one costs
  the remote at most a briefly-open stream we no-op as unknown.
- Unlike a queued pong/GoAway, queued RSTs do NOT gate the read branch
  of `poll`. This is deliberate: gating reads behind an un-sendable RST
  would let a hostile SYN burst freeze the whole session — every
  stream, the control channel included — until the socket drains or
  the keepalive fires. The send loop drains the queue one frame per
  iteration (FIFO `pop_front`) at the same site the original single
  slot drained: after pongs/GoAways and before stream frames, with no
  extra wake mechanism — while the socket is writable the whole queue
  goes out within one poll round. `close()` flushes the whole queue
  with the other pending frames.

### Wire semantics

- The receiving yamux-rs side already handles inbound `RST` frames
  per-stream (`on_data` / `on_window_update` RST arms: that stream
  closes, `Action::None`), so the opener's refused stream dies while
  the session survives. Go's yamux fork likewise processes `flagRST`
  per-stream from both Data- and WindowUpdate-typed frames
  (`stream.go` `processFlags`).
- The rejected SYN's body (if any) is dropped with the frame; the
  stream is never created, and `Reset` short-circuits the handler
  before any code that assumes the stream exists.

### Upgrade note

When bumping yamux upstream: re-apply the `Action::Reset` machinery
above to the new `src/connection.rs` (the `Action` enum variant, the two
cap sites, the `pending_reset_frames` bounded queue + send-loop +
`close()` wiring, and the read-gate exception), or — better — carry the
patch upstream. The other deviations from crates.io yamux 0.14.0 are
listed below.

## Patch: separate mpsc `Sender` for window updates (read-side lost-wakeup deadlock)

`futures::channel::mpsc` assumes a single task polls each `Sender` for
readiness. While a `Sender` is parked (queue full), `poll_ready` stores
the polling task's waker in the shared `sender_task` handle, and the
receiver's `unpark_one` wakes exactly that stored waker when capacity
frees. If two tasks poll the *same* `Sender`, a `poll_ready` from task B
overwrites task A's stored waker — the next `unpark_one` wakes B (or
nobody, when the handle was re-parked with `task = None`) and A stays
parked forever: a lost wakeup.

Upstream yamux puts one `mpsc::Sender<StreamCommand>` in `Stream` and
polls it from both the write path (`poll_write`/`poll_close`) and the
read path (`poll_read`/`poll_next` → `send_window_update`). A stream
driven through `tokio::io::split` halves (two tasks, serialized by the
`BiLock`) hits the race: while the writer is parked on a full queue, the
reader's `send_window_update` polls the same `Sender`, overwrites the
stored waker, and the writer is orphaned — the transfer hangs forever
with both directions idle. Reproduced intermittently (~7.5% of runs) by
`frp-core/tests/mux.rs::mux_2mib_bidirectional_byte_exact` (2 MiB each
way over a 1 MiB duplex, 4 tasks, `tokio::io::split`), in either
direction, and in the `poll_close` park as well.

### What changed (src/connection/stream.rs only)

- `Stream` gains `sender_wu: mpsc::Sender<StreamCommand>` — a clone of
  the same channel, constructed in `new_inbound`/`new_outbound`.
- `send_window_update` polls/start_sends via `sender_wu` instead of
  `sender`. Data frames and `CloseStream` keep using `sender`.

The write and read task domains each own their `Sender`, so a parked
writer's stored waker is never overwritten by the reader's polls. The
channel's guaranteed-slot accounting (capacity = buffer + senders)
covers both handles; `parked_queue` wakes whichever sender is parked,
FIFO.

### Upgrade note

When bumping yamux upstream: re-apply the `sender_wu` field, the two
constructor clones, and the `send_window_update` sender swap. Carry
both of these patches upstream if possible.

## Patch: per-stream receive-window cap (Go `MaxStreamWindowSize` parity)

crates.io yamux auto-tunes each stream's receive window up to the
connection-wide limit (`Config::set_max_connection_receive_window`):
with a large connection window, a single stream can claim hundreds of
MiB (e.g. ~320 MiB at a 384 MiB connection window with 256 streams). Go
frp pins `MaxStreamWindowSize = 6 MiB` (`util/conn.go`), bounding how
much in-flight data one stream can demand of us.

frp-rs sets this cap on the XTCP tunnel session
(`frp-core/src/xtcp_session.rs`, 6 MiB). This is a receive-side policy
change only: the cap bounds the credit we grant per stream, so the only
wire-visible effect is smaller window-update increments — no framing
change, and Go peers are unaffected.

### What changed

- `Config` gains `max_stream_receive_window: Option<u32>` (default
  `None` = crates.io auto-tuning) and
  `Config::set_max_stream_receive_window` (`src/lib.rs`), which asserts
  the cap is `>= 256 KiB (DEFAULT_CREDIT)`.
- `FlowController::next_window_update` clamps the auto-tuned
  `max_receive_window` to the cap (`src/connection/stream/flow_control.rs`).
  The cap only limits GROWTH and only when it is above the current max
  (a window that already exceeds the cap is left unchanged), preserving
  the accumulated-credit accounting invariants.

### Upgrade note

When bumping yamux upstream: re-apply the `Config` field + setter and
the `flow_control.rs` clamp, or carry the patch upstream.

## Patch: window-growth seed RTT (warm-start of the per-stream window ramp)

crates.io yamux doubles a stream's receive window only when the peer has
drained half of its credit in less than two round-trips (QUIC-style BDP
auto-tuning), and it evaluates that condition **only when a PING/PONG RTT
sample exists** — the gate is literally
`.rtt.get().map(|rtt| elapsed < rtt * 2).unwrap_or(false)`
(`src/connection/stream/flow_control.rs`). The first ping is sent as soon
as the connection is polled (`Rtt::new` arms `next`, so `next_ping` fires
on the first iteration — `src/connection/rtt.rs`), but the sample still
arrives a full RTT later. For that first round-trip the `.unwrap_or(false)`
arm wins and the window never grows, so a fresh stream is pinned at
`DEFAULT_CREDIT` (256 KiB): at 100 ms RTT a single tcp-mux stream is
capped at ~20 Mbit/s until the sample lands, then ramps. Go frp's yamux
fork sidesteps this by pinning 6 MiB per stream outright
(`util/conn.go` `MaxStreamWindowSize`) with no growth gate at all.

frp-rs keeps the auto-tuning (it is the only bound that adapts to the
actual BDP) but removes the dead first round-trip: while the connection
has no sample of its own, a **conservative seed RTT (100 ms)** is
substituted for the missing measurement. Growth then requires what the
real gate requires anyway — the peer drained half of `DEFAULT_CREDIT`
that is 128 KiB within `2 * 100 ms`, i.e. it is running at >= 5.2 Mbit/s,
which is exactly "the BDP exceeds the current window" for any link with
RTT <= 100 ms. Nothing else changes: the seed is only consulted when
`Rtt::get()` is `None`, it never widens a measured RTT, growth is still
bounded by `max_connection_receive_window` / `max_stream_receive_window`
(the second patch), and a peer that drains its credit slower than the seed
window keeps the 256 KiB window. This is perf-audit TOP 5 / Phase 2-2,
option (b).

### What changed

- `Config` gains `window_growth_seed_rtt: Option<Duration>` and
  `Config::set_window_growth_seed_rtt` / `Config::window_growth_seed_rtt`
  (`src/lib.rs`). **The fork's `Config::default()` is `Some(100 ms)`** —
  a deliberate deviation from crates.io (documented in the `Config` doc
  header); `None` restores upstream gating exactly. Because the seed rides
  in on the default, every frp-rs yamux user gets it without opting in:
  the tcp-mux config builder (`frp-core/src/mux.rs`, pinned by
  `yamux_config_carries_window_growth_seed_rtt`) and the XTCP tunnel
  session (`frp-core/src/xtcp_session.rs`), both of which start from
  `Config::default()`.
- `FlowController::next_window_update` evaluates
  `self.rtt.get().or(self.config.window_growth_seed_rtt)` through the new
  pure `window_growth_gate_open(assumed_rtt, since_last_window_update)`
  helper (`src/connection/stream/flow_control.rs`); the multiplication is
  `saturating_mul` so a nonsensical configured seed cannot overflow.
- `assert_invariants`'s "the maximum is only increased iff an rtt
  measurement is available" check now applies only when no seed is
  configured, i.e. it still pins the upstream configuration.
- Tests: `mod window_growth_tests` in `flow_control.rs` (gate matrix
  including the `None`/upstream row, no-sample doubling, slow-consumption
  no-growth, and "a sample wins over the seed"), plus the frp-core wiring
  pin above. Note that this vendored crate is not a workspace member, so
  its unit tests are not part of `cargo test --workspace`; run them with a
  standalone checkout of the crate (`mod tests` there is quickcheck-based
  and needs a `quickcheck` dev-dependency added, which the normalized
  `Cargo.toml` does not carry).

### Upgrade note

When bumping yamux upstream: re-apply the `Config` field + accessors +
default, the `assumed_rtt` fallback in `next_window_update` (and the
`saturating_mul`), and the `assert_invariants` guard, or carry the patch
upstream. `WINDOW_GROWTH_SEED_RTT` (`src/lib.rs`) holds the value.

## Patch: send-side body-buffer pool (no per-chunk `Vec` allocation)

Every data frame on the write path built its body with
`Vec::from(&buf[..k])` — one fresh allocation + copy per chunk
(k ≤ `split_send_size`, 16 KiB default) on the default tcp-mux data
plane; Go's fatedier/yamux fork writes the user slice zero-copy. This
was the last per-chunk allocation in the frp-rs bridge data path.

### What changed

- `Connection::new` creates a connection-scoped
  `crossbeam_queue::ArrayQueue<Vec<u8>>` (cap 16, ≤ ~256 KiB per
  connection with the 16 KiB default) and threads it into `frame::Io`
  and every `Stream` (`src/connection.rs`, `src/connection/stream.rs`).
- `Stream::poll_write` pops a buffer from the pool and copies the chunk
  into it instead of allocating (`src/connection/stream.rs`); a full
  pool just allocates fresh — the pool is a cache, not a guarantee.
- `frame::Io` returns the body to the pool when the frame is fully
  written — `WriteState::Body` completion in `poll_ready`
  (`src/frame/io.rs`), the point where the body `Vec` becomes
  exclusively owned and would otherwise be dropped. Buffers with
  capacity above `DEFAULT_SPLIT_SEND_SIZE` (custom `split_send_size`),
  and any lost to WriteZero / Poisoned / teardown, are simply dropped —
  the pool dies with the connection.
- New dependency: `crossbeam-queue = "0.3"` (`Cargo.toml`), already in
  the workspace dependency tree (frp-core's KCP chunk pool uses the
  same queue), so no new crates enter the build.

### Red line: send-side only

The pool must NOT extend to the read side: read bodies are allocated
per-frame (`vec![0; body_len]` in `ReadState::Body`,
`src/frame/io.rs` — Go-parity per-frame make, out of scope) and move
into `Shared::buffer` (`Chunks`), where `Stream::poll_read` consumes
them lazily, long after the frame object is dropped. Returning a read
body to the pool at driver time would be a use-after-free. The return
point above is exclusively on the write path.

### Why this is not the round-4 batched write path

The earlier batched-write attempt (reverted, 114 vs 150.1 MB/s) changed
write timing and packetization. This patch only reuses the allocation:
frame boundaries, write timing, and the header-then-body Sink structure
are unchanged, so throughput behavior is preserved.

### Upgrade note

When bumping yamux upstream: re-apply the `body_pool` field threading
(`Connection::new`/`Active`/`Io`/`Stream`) and the two hunk sites
(`poll_write`, `WriteState::Body` completion), or carry the patch
upstream.

## Minor deviations (not patches)

- `frame::header::internal_error()` / `Frame::internal_error()` (GoAway
  code 2) carry `#[allow(dead_code)]` (`src/frame/header.rs`,
  `src/frame.rs`): the only caller — the inbound stream-cap `Terminate`
  arm in `src/connection.rs` — now sends a per-stream Reset. Kept for
  upstream parity; benign, remove when upstream drops them.

## Diff from crates.io yamux 0.14.0

Everything else in this tree is byte-identical to crates.io yamux
0.14.0; the full delta is the five patches above plus the two
`#[allow(dead_code)]` annotations.
