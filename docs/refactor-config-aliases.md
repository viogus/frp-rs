# One name, seven places: the configuration alias layer

Status: **design note plus four verified defects; three of them are fixed in
this change and the fourth (the inventory drift the parity test would catch) is
still open.**
This replaces an earlier draft whose central premise was wrong; the review that
falsified it is recorded in the PR. The correction is kept visible here because
the wrong version is the intuitive one: the strict check does **not** run on the
raw file.

## The order that actually runs

`frp-core/src/config/normalize.rs` is the entry point for every config file. It
parses to a `toml::Value`, calls `normalize(&mut value, format)`, and only then
validates: `run_strict_check_top_level` for `.ini` (the deprecation path) and
`run_strict_check` for everything else. `frp-core/src/config/file.rs` does not
call either function; it threads the `known_server_keys` / `known_client_keys`
function pointers into `load_config_from_file`.

`normalize` itself, on the server, in this order: hoists a fixed list of
snake_case root keys into `[transport]`, flattens `[transport.tls]` onto the
legacy top-level TLS fields, hoists a **second**, camelCase-keyed list of root
keys (`heartbeatTimeout`, `maxPoolCount`, `tcpKeepalive`, …), and applies the
Go camelCase rename table **last** — and only inside `[transport]`, so a
camelCase key written at the root is never reached by it. On the client the
order is the same until the end, where `[transport.x]` is flattened to root `x`
generically.

Then `serde` runs, and its `#[serde(alias = "…")]` attributes accept one extra
spelling per field.

So there are **three** registration points, all after parsing: the strict lists,
the normalizer's hoist/rename tables, and the serde aliases. A name is reachable
only if the normalizer or serde knows it, and acceptable only if the strict list
knows the spelling *as it arrives at the check* — which is after the rename pass,
for the names the rename pass covers.

Inventory, measured on the working tree: 115 + 92 `#[serde(alias)]` and 5 + 5
`rename` attributes on the server/client config sources; 7 `flatten_to_table`
call sites; 27 root-level rename pairs (plus per-table arms further down); two
root strict lists of 110 and 100 entries (97 distinct on the client, which
repeats three spellings) plus one arm per section and nine `*KNOWN_KEYS` arrays;
and 168 + 132 `pub` field declarations across the whole of
`frp-core/src/config/server.rs` / `client.rs` (the top-level `ServerConfig` itself
has 44 — the larger figure is the file, not the struct).

## Four defects this layer already has (1–3 fixed here, 4 open)

All four were reproduced by running `verify` on a config that uses them — three
on `frps`, one on `frpc` — i.e. through the strict path, not through the
strict-free `load_*_config_from_str` helpers that every `test_parse_*` test uses:

1. **Accepted, then dropped.** `tcpMux = true` (and `tcpMuxKeepaliveInterval`,
   `tcpMuxKeepaliveTimeout`) at the root of `frps.toml` prints
   `the configuration file … syntax is ok`, but the hoist list carries only the
   snake_case spellings and `ServerConfig` has no root field for them, so the
   value is discarded. Same shape for `tls_skip_verify` / `tlsSkipVerify` at the
   root of `frps.toml`: they are in the **server** strict list but are a
   **client** field, so a server config that sets them is silently ignored.
2. **Reachable, unlisted — refused on the client before this change.** `[transport.tls]
   useSystemCa = true` in `frpc.toml` is a documented setting, and the default
   strict mode refuses it with
   `Config file /tmp/c1.toml is invalid: unknown field "tls_use_system_ca"`.
   The client normalizer flattens the table to the root key `tls_use_system_ca`
   and `known_client_keys()` never learned that name, so a setting the docs
   advertise cannot be used in the configuration the docs recommend. This is the
   same shape as defect 3, on the other binary, and it is the reason the
   onboarding checklist tells contributors to register a key in three places.
3. **The error names an internal key.** `[transport.tls] useSystemCa = true` in
   `frps.toml` is hoisted to the root key `tls_use_system_ca` *before* the check,
   which is not in `known_server_keys()`, so the user gets
   `unknown field "tls_use_system_ca" in config file …` while `docs/config.md`
   promises Go's own message for that spelling. Nothing about the ordering is
   wrong here — the list is simply missing the key the hoist produces.

Defect 1 and 3 are the same shape seen from opposite ends: the hoist and the
strict list disagree about the name. Defects 2 and 3 are one bug on two
binaries — the hoist produces a root key the list never learned. No test catches either, because `test_parse_*` never runs the strict
check, and the array-element parity test
(`strict_array_element_keys_match_struct_fields`) covers only the nine
`*KNOWN_KEYS` arrays — the two root lists are explicitly out of its scope.

## What to do about it

**Fix the three defects first, with a parity test, and only then consider a
new table.** A table that generates the lists is worth it only when the lists
have stopped lying; otherwise it generates the same lies faster.

The parity test is the load-bearing piece. Two layers, cheapest first:

- **A source-derived unit test.** `frp-core/src/config/tests.rs` already reads the
  config sources with `include_str!`, so a test can assert that every `pub` field
  and every `#[serde(alias)]`/`rename` spelling in `frp-core/src/config/server.rs`
  and `client.rs` appears in the list the corresponding section validates
  against, and that every strict-list key resolves to a field or an alias. About
  fifty lines, no new machinery, and it *enumerates* the defect-2 population
  instead of guessing at it. The strict path is also unit-testable directly —
  `load_client_config(path, true)` runs the full check, unlike the lenient
  `load_*_config_from_str` helpers every `test_parse_*` test uses.
- **A CLI layer** for what a unit test cannot see: `frps`/`frpc verify` exit
  codes, the `.ini` top-level-only strictness, and the `--strict-config=false`
  escape hatch.

Both assert

- every spelling in a list is *accepted* by that binary in that section
  (kills defect 1 and the "one list is in the wrong mode" variant), and
- every serde alias and every hoisted key is in the list the section validates
  against (kills defect 2 and 3).

That is a test over the CLI, not over `load_*_config_from_str`, because the
helpers deliberately skip the strict layer and asserting through them is what
let all three defects survive.

**Design A, re-scoped.** One `knobs` table — `canonical`, `spellings`, `scope` —
that drives the rename pass and generates both strict lists, with the structs
carrying no `alias` attributes, is still the right end state: a spelling that is
not in the table then cannot be validated, and one that is cannot be
unreachable. Two surfaces have to be priced in that the first draft missed:

- **The frpc admin API deserializes the same structs straight from JSON**
  (`frp-client/src/admin.rs`, `Json(proxy): Json<ProxyConfig>`), with no
  normalizer and no strict check. The `ProxyConfig` aliases (`localIP`,
  `secretKey`, `customDomains`, `httpUser`, …) exist for that surface as much as
  for config files, so the table would need a second application point or the
  admin API would silently stop accepting camelCase.
- **The lists are not generated today and there are more than two**: two root
  lists plus one arm per section plus nine `*KNOWN_KEYS` arrays, and the
  `known_client_keys()` / `known_server_keys()` split means one table has to
  carry a *scope* per spelling, not just a canonical name.

Cost stays "wide but mechanical": roughly 200 rows replacing 207 attributes, one
new file, and a migration that has to touch the admin surface deliberately.

## Honest accounting of the per-knob cost

The onboarding checklist has ten steps, and a table removes three of them (the
serde alias, the strict-list entry, the hoist or flatten entry — design A drives
all three). The rest — restart-only bookkeeping, a config test, the
`docs/config.md` row, the Go-column suite row, the `CHANGELOG.md` bullet, and the
citation-table regeneration that any `docs/config.md` edit triggers — remain. So the realistic post-table cost is **seven touch points, not
two**, and the citation table is still regenerated per knob. Saying otherwise
would repeat the mistake this note was written to correct.

## Out of scope, deliberately

- No new dependency; the parser, the serde derive and the strict mode stay.
- Go's camelCase spellings stay: a Go frp config must keep loading unchanged.
  Removing list entries is therefore *not* a safe simplification — see defect 1,
  which is the opposite direction.
- `docs/config.md`'s table structure stays; it and the Go-column suite are the
  contract that keeps the reference honest.

## Recommended order

1. **Shipped 2026-11-20 (root lists only).** The source-derived parity test
   now covers `known_server_keys()` and `known_client_keys()`: every camelCase
   entry must be either a spelling `serde_keys_of_struct` derives from the
   struct or a key `normalize_*_config` rewrites away, and the failure message
   names the offenders. Section and array-element lists already had this
   guarantee through `strict_array_element_keys_match_struct_fields`. The tests
   are in `frp-core/src/config/tests.rs`
   (`strict_server_root_list_only_names_spellings_the_struct_can_consume`,
   `strict_client_root_list_only_names_spellings_the_struct_can_consume`); the
   reverse direction (a serde spelling strict mode refuses) is still open,
   because `useSystemCa` is a legal root alias here while Go documents it only
   under `[transport.tls]`, so refusing the root form is intended. Defect 2 is
   therefore closed at the root lists and unmeasured below them.
2. Fix what it prints, in one PR: the three named defects, the client
   `useSystemCa` instance, and the `docs/naming.md` line that currently documents
   a root `tcpMux` being "accepted and then ignored" as intended behaviour.
3. The CLI layer of the test, for exit codes, `.ini` strictness and the
   `--strict-config=false` path.
4. Re-measure the per-knob cost with the tests in place.
5. Design A, if the parity test shows the lists can be trusted long enough to
   migrate them.
