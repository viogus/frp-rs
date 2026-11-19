# One name, seven places: the configuration alias layer

Status: **design note plus three verified defects — no behaviour has changed.**
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

`normalize` itself, in order: hoists a fixed list of root keys into
`[transport]` (snake_case only), renames a table of Go camelCase spellings,
flattens `[transport.tls]` onto the legacy top-level TLS fields, and — on the
client — flattens `[transport.x]` to root `x` generically.

Then `serde` runs, and its `#[serde(alias = "…")]` attributes accept one extra
spelling per field.

So there are **three** registration points, all after parsing: the strict lists,
the normalizer's hoist/rename tables, and the serde aliases. A name is reachable
only if the normalizer or serde knows it, and acceptable only if the strict list
knows the spelling *as it arrives at the check* — which is after the rename pass,
for the names the rename pass covers.

Inventory, measured on the working tree: 115 + 92 `#[serde(alias)]`, 5 + 5
`rename`, 109 + 86 distinct spellings, 9 `flatten_to_table` call sites, 24 rename
pairs, two root strict lists plus one arm per section, and 166 + 131 `pub` fields
across the whole of `frp-core/src/config/server.rs` / `client.rs` (the top-level
`ServerConfig` itself has 44 — the larger figure is the file, not the struct).

## Three defects this layer already has

All three were reproduced with `frps verify -c`, i.e. through the strict path,
not through the strict-free `load_*_config_from_str` helpers that every
`test_parse_*` test uses:

1. **Accepted, then dropped.** `tcpMux = true` (and `tcpMuxKeepaliveInterval`,
   `tcpMuxKeepaliveTimeout`) at the root of `frps.toml` prints
   `the configuration file … syntax is ok`, but the hoist list carries only the
   snake_case spellings and `ServerConfig` has no root field for them, so the
   value is discarded. Same shape for `tls_skip_verify` / `tlsSkipVerify` at the
   root of `frps.toml`: they are in the **server** strict list but are a
   **client** field, so a server config that sets them is silently ignored.
2. **Reachable, unlisted.** A field with a serde alias whose spelling is missing
   from the list is rejected by default and accepted only in lenient mode. This
   class has already shipped once (recorded in `docs/history/development-log.md`)
   and is the reason the onboarding checklist tells contributors to register a
   key in three places.
3. **The error names an internal key.** `[transport.tls] useSystemCa = true` in
   `frps.toml` is hoisted to the root key `tls_use_system_ca` *before* the check,
   which is not in `known_server_keys()`, so the user gets
   `unknown field "tls_use_system_ca" in config file …` while `docs/config.md`
   promises Go's own message for that spelling. Nothing about the ordering is
   wrong here — the list is simply missing the key the hoist produces.

Defect 1 and 3 are the same shape seen from opposite ends: the hoist and the
strict list disagree about the name. Defect 2 is the serde aliases and the list
disagreeing. No test catches either, because `test_parse_*` never runs the strict
check, and the array-element parity test
(`strict_array_element_keys_match_struct_fields`) covers only the nine
`*KNOWN_KEYS` arrays — the two root lists are explicitly out of its scope.

## What to do about it

**Fix the three defects first, with a parity test, and only then consider a
new table.** A table that generates the lists is worth it only when the lists
have stopped lying; otherwise it generates the same lies faster.

The parity test is the load-bearing piece, and it has to run where the bug
lives: drive a real `frps --verify` / `frpc --verify` over a generated config
per section, with one spelling per entry of the strict list, and assert

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

The onboarding checklist has ten steps, and a table only removes two of them
(the list entry and the alias). The rest — restart-only bookkeeping, a config
test, the `docs/config.md` row, the Go-column suite row, the `CHANGELOG.md`
bullet, and the citation-table regeneration that any `docs/config.md` edit
triggers — remain. So the realistic post-table cost is **seven touch points, not
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

1. Three defect fixes plus the CLI-driven parity test, as one PR.
2. Re-measure the per-knob cost with the parity test in place.
3. Design A, if the parity test shows the lists can be trusted long enough to
   migrate them.
