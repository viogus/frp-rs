# The server's bridge decision table

**Status:** the plain-path predicate is named and tested (`PlainPath`, PR #644).
The two remaining arms still run their bodies inline; this table is the input for
collapsing them.

## The seven decisions in `frp-server/src/control/bridge.rs`

`run_work_bridge` picks a bridge shape from what the request and the proxy carry.
The order matters — an earlier arm shadows every later one — and each condition
records an incident.

| # | Condition | Shape | Why the condition exists |
|---|---|---|---|
| 1 | work connection is encrypted (proxy `use_encryption`) and a header injector applies | `bridge_encrypted_decompressed_read` | The injector sits above the decompressor, so the read side must already be a reader |
| 2 | work connection is encrypted | `bridge_encrypted_io` | Whole-pair entry point: it splits internally and keeps one monomorphization |
| 3 | XTCP/STCP visitor fallback | `relay_plain_pooled` | `splice` needs a raw `IoStream`, and the pooled relay does not join forever when one side goes idle |
| 4 | a bandwidth limit is configured | `bridge_plain_rate_limited[_decompressed_read]` | One bucket covers both directions; the injector variant as in row 1 |
| 5 | no compression, no VHost pre-read, no injector, no visitor-segment wrapping | `relay_plain_fast` | The only shape `splice(2)` can take; every excluded term would need a userspace reader |
| 6 | anything else | `bridge_plain[_decompressed_read]` | Split both sides and let the core (de)compress / inject |
| 7 | (SUDP) datagram proxy | `frp-server/src/control/bridge/sudp.rs` | Not a stream bridge at all; compression is forced off because the Snappy stream would misread datagram boundaries |

## What collapse must preserve

- **Order.** Rows 1-2 are checked on the proxy's encryption flag before anything
  looks at compression; rows 3-4 before the fast-path test. `PlainPath` encodes
  rows 3-6 in that order, and the two encrypted rows stay above it.
- **Where the split happens.** Visitor wrapping (`try_split_user_side`) and the
  VHost injector must be applied *after* the plan chooses a shape and *before*
  the core runs — the injector owns the absolute response-head deadline, and the
  bridge is deliberately not given a one-shot timeout.
- **The pre-read hand-off.** `bridge_pre_read` is injected on the slow paths
  only; the fast relay has nowhere to put it, which is why `BridgePlan::choice`
  must never answer `PlainFastRelay` for a plan that carries bytes (pinned in
  `frp-core/src/bridge.rs`).

## Why the remaining arms are not collapsed yet

Rows 3 and 4 each need a different user side: row 3 takes a `UserSide` pair and
the pooled relay's own error handling, row 4 needs the injector branch inside it.
Collapsing them into `match plain_path(..)` is a 120-line move whose diff a
reviewer cannot tell apart from a behaviour change, so it wants its own PR with
this table as the checklist.
