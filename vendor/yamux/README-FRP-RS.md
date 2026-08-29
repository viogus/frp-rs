# Vendored yamux 0.14.0 (frp-rs)

This directory vendors `yamux` 0.14.0 (crates.io, Parity Technologies)
with two patches, wired in via `[patch.crates-io]` in the workspace
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
  Data-typed frame with the `RST` flag for `id` into
  `pending_read_frame` — the same frame shape the crate already sends
  when a stream handle is dropped without `poll_close`
  (`on_drop_stream`, `State::Open` arm).

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

When bumping yamux upstream: re-apply the three hunks above to the new
`src/connection.rs` (the `Action` enum, the two cap sites, and the
dispatch arm), or — better — carry the patch upstream. The rest of this
tree is byte-identical to crates.io yamux 0.14.0.

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
both patches upstream if possible.
