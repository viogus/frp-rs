# The bridge entry points, as data

**Status:** slice 1 of 3 shipped. The nine public bridge functions are now thin
wrappers over one `BridgePlan`; the two dispatchers still derive the case
analysis by hand, and 53 call sites still pick a function by name.

## The shape that was there

`frp-core/src/bridge.rs` exposed eight bidirectional entry points plus the
splice fast path:

| Entry point | Crypto | user→work compress | work→user decompress | Limiter | Split |
|---|---|---|---|---|---|
| `bridge_plain` | none | `use_compression` | `use_compression` | no | caller |
| `bridge_plain_decompressed_read` | none | `use_compression` | no | no | caller |
| `bridge_plain_rate_limited` | none | `use_compression` | `use_compression` | yes | caller |
| `bridge_plain_rate_limited_decompressed_read` | none | `use_compression` | no | yes | caller |
| `bridge_encrypted` | AES-128-CFB | `use_compression` | `use_compression` unless `read_is_decrypted` | yes | caller |
| `bridge_encrypted_decompressed_read` | AES-128-CFB | `use_compression` | no | yes | caller |
| `bridge_encrypted_io` | AES-128-CFB | `use_compression` | `use_compression` | yes | this function splits |
| `relay_plain_pooled` / `bridge_splice` | none | no | no | no | pooled buffers / `splice(2)` |

Five independent axes were being encoded as eight function names, and two
dispatchers re-derived the combination at their call sites
(`frp-server/src/control/bridge.rs`, `frp-client/src/proxy.rs`). Nothing was
wrong with any single function; the cost was that adding an axis (the
round-14 A1 "read side already decrypted" flag did exactly this) means editing
every entry point, both dispatchers, and every caller that has to choose.

## What slice 1 changes

- `BridgePlan` holds the axes: `crypto` (`Plain` | `Encrypted { key }`),
  `compress`, `read_side` (`Decompress` | `AlreadyPlain`), `pre_read`,
  `limiter`, `metrics`. Builders are `BridgePlan::plain(compress)` and
  `BridgePlan::encrypted(key, compress)`, plus chainable `read_side`,
  `pre_read`, `limiter`, `metrics`.
- `BridgePlan::run(user_r, user_w, work_r, work_w)` derives the three booleans
  the cores take in one place (`fn core_flags`) and calls the matching core.
  Entry points are now three lines each; their signatures and behaviour are
  unchanged.
- `bridge_plain_rate_limited_core` was deleted: it was `bridge_plain_core` with
  a different debug line, and nothing else. One core per crypto mode now.

The one visible API change: the plain entry points' `work_r` parameter gained
`+ Send`, because `BridgePlan::run` is shared with the encrypted path, which
moves the reader into a task. Every caller passes a tokio stream or
`tokio::io::split` half, which is `Send`, so no call site changed.

## What slice 1 does not do

- The two dispatchers still branch on `(encrypted, compressed, limited,
  injector)` by hand. Slice 2 replaces those branches with plan construction, so
  the choice appears once per binary instead of once per branch.
- Call sites that name a function (`bridge_plain`, …) keep naming it. Slice 3
  only has to happen if the plan earns it: the public functions stay as the
  stable surface, and the plan is allowed to become the internal one.
- `relay_plain_pooled` and `bridge_splice` stay separate. They are the promise
  the plan is not: pooled buffers and a kernel fast path, chosen by capability
  (`try_tcp`), not by configuration.

## Evidence

`bridge_plan_keeps_the_entry_point_semantics` pins the eight historical
combinations against `core_flags`; `bridge_plan_defaults_leave_the_optional_axes_off`
pins the defaults. The 40 tests in `frp-core/src/bridge.rs`'s `mod tests`
(the byte-moving ones) were untouched and still pass, which is what says the
rewiring did not change behaviour: they exercise each entry point through real
pipes.
