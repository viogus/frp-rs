# The bridge entry points, as data

**Status:** slice 1 of 3 shipped. The seven flag-bearing public bridge functions
are now thin wrappers over one `BridgePlan` (`relay_plain_pooled` and
`splice::bridge_splice` stay outside it: they are chosen by capability, not
configuration); the two dispatchers still derive the case analysis by hand, and
26 non-test call sites in `frp-server/src` and `frp-client/src` still pick a
function by name.

## The shape that was there

`frp-core/src/bridge.rs` exposed eight bidirectional entry points plus the
splice fast path:

| Entry point | Crypto | user→work compress | work→user decompress | Limiter | Split |
|---|---|---|---|---|---|
| `bridge_plain` | none | `use_compression` | `use_compression` | no | caller |
| `bridge_plain_decompressed_read` | none | `use_compression` | no | no | caller |
| `bridge_plain_rate_limited` | none | `use_compression` | `use_compression` | yes | caller |
| `bridge_plain_rate_limited_decompressed_read` | none | `use_compression` | no | yes | caller |
| `bridge_encrypted` | AES-128-CFB | `use_compression` | `use_compression` (independent of `read_is_decrypted`) | yes | caller |
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
  `compress`, `decompress_read`, `read_is_plaintext`, `pre_read`, `limiter`,
  `metrics`. Builders are `BridgePlan::plain(compress)` and
  `BridgePlan::encrypted(key, compress)`, plus chainable `read_is_plaintext`,
  `without_read_decompression`, `pre_read`, `limiter`, `metrics`.
- Decompression and decryption stay **separate** axes. The first draft collapsed
  them into one `ReadSide` enum; the adversarial review caught that
  `bridge_encrypted(read_is_decrypted = true, compression on)` used to pass
  `decompress_read = use_compression` (base `frp-core/src/bridge.rs:729-741`) and
  the collapse silently stopped decompressing a stream that is decrypted but
  still snappy-compressed. `core_flags` therefore reads three independent
  booleans, and the entry points fix their pairs explicitly.
- `BridgePlan::run_plain` / `run_encrypted` call the matching core. Keeping two
  methods is what lets the plain entry points keep their original
  `impl AsyncReadExt + Unpin` bound: the `Send` requirement belongs to the
  encrypted core's boxed reader, not to the plan.
- `bridge_plain_rate_limited_core` was deleted: it was `bridge_plain_core` with
  a different debug line, and nothing else. One core per crypto mode now.

No public signature changed: the plan is split into `run_plain` and
`run_encrypted` precisely so the plain entry points do not inherit the encrypted
core's `Send` bound.

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

`bridge_plan_keeps_the_entry_point_semantics` pins ten combinations — the eight
entry points plus the two `read_is_decrypted` values for `bridge_encrypted`, one
of which is the case the first draft got wrong —
`bridge_plan_defaults_leave_the_optional_axes_off` pins the defaults, and
`without_read_decompression_keeps_the_write_side_compressing` pins the axis that
is easy to collapse again. The existing byte-moving tests in `frp-core/src/bridge.rs`'s
`mod tests` were untouched and still pass; they cover most but **not all** entry
points (the two `*_decompressed_read` variants have no dedicated test; the
`_rate_limited` pair is exercised by `test_bridge_plain_rate_limited_bandwidth`
and friends), so the flag table above is the evidence for those, not the pipe
tests — and it pins only the derivation, not what each wrapper passes to its
builder.
