# Vendored yamux 0.14.0 (frp-rs)

This directory vendors `yamux` 0.14.0 (crates.io, Parity Technologies)
with one small patch, wired in via `[patch.crates-io]` in the workspace
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
