# One name, seven places: a design note for the configuration alias layer

Status: **design only — no code in this document has landed.** Written after the
onboarding-cost audit took the same measurement twice from different directions
(a newcomer reading the config layer, and the author of a one-field change
watching what it cost to land).

The problem is not that the configuration layer is large. It is that **one
name** — say `tcp_mux` — is maintained in up to seven independent places, none of
which knows about the others, and three of which fail **silently** when they
disagree.

## What exists today

Three mechanisms move a value from a file into a struct, applied in this order:

1. **Strict validation** on the raw parsed table (`frp-core/src/config/file.rs`
   calls `run_strict_check_top_level` / `run_strict_check`). The accepted
   spellings come from hand-written lists in `frp-core/src/config/strict.rs`:
   `known_server_keys()`, `known_client_keys()`, and one arm per nested section
   in `section_known_keys()`.
2. **Normalization** on the table, before deserialization
   (`frp-core/src/config/normalize.rs`): the server *hoists* a fixed list of root
   keys into `[transport]` and then applies a rename table; the client is
   *flattened* generically (`other => other`), so `[transport.x]` becomes root
   `x` for any `x`.
3. **`serde` aliases** on the structs (`frp-core/src/config/server.rs`,
   `frp-core/src/config/client.rs`) accept a second spelling for a field when
   both survive the first two steps.

Measured inventory (working tree, 2026-11-20):

| Surface | Count |
|---|---|
| `pub` fields on the server/client config structs | 166 / 131 |
| `#[serde(alias = "…")]` attributes | 115 / 92 |
| `#[serde(rename = "…")]` attributes | 5 / 5 |
| distinct spellings across those attributes | 109 / 86 |
| `flatten_to_table(` call sites in the normalizer | 9 |
| `("camel", "snake")` rename pairs in the normalizer | 24 |
| hand-written strict lists | 2 root lists + one arm per section |

So a single new knob needs: the struct field, a serde alias, an entry in the
root list or a section arm, a hoist or flatten entry, a `docs/config.md` row (in
the right table of 18), a row in the Go-column suite, a `CHANGELOG.md` bullet,
and — because prose moves — a regeneration of the 604-row citation table. That
is the "one knob, nine touch points" checklist in `docs/naming.md`; the point of
this note is to shrink it to a table row plus a doc row.

## Why it matters: the three silent failure modes

Each of these has cost a real CI round or a real review finding:

- **Listed but unreachable.** A key passes strict validation because someone
  added it to the list, but nothing hoists or flattens or aliases it, so `serde`
  never sees it. Landed once with a flat `workerThreads` (accepted, ignored) and
  once with a documented `[transport]` key that was refused as unknown because
  the section list had not been taught the name.
- **Reachable but unlisted.** An alias exists on the struct, the strict list does
  not know it, so the documented spelling is rejected by default and accepted
  only in lenient mode. Two occurrences on the same day.
- **Both, in opposite directions.** The same camelCase name appears in a root
  list and in a section arm, and the two disagree about which section owns it.

None of the three is caught by a test, because every test that exists checks
behaviour for a spelling that already works.

## Candidate designs

### A. One table drives everything

A single `knobs` table in `frp-core/src/config/` declares each knob once:

```rust
struct Knob {
    canonical: &'static str,        // tcp_mux
    spellings: &'static [&'static str], // &["tcp_mux", "tcpMux"]
    scope: Scope,                   // Root | Section("transport") | ArrayElement("httpPlugins")
}
```

- Normalization renames every spelling to `canonical` before deserialization, so
  the structs carry **no** alias attributes.
- The strict lists are generated from the table (`keys_for(scope)`), so a
  spelling cannot be validated without also being reachable.
- `docs/config.md` rows can be checked against the table in a test, because the
  table is data.

Cost: every `#[serde(alias)]` in two files is deleted and re-expressed as a row
(≈200 rows, mechanical but wide), and the table becomes a new place to learn.
Benefit: the three silent failure modes become unrepresentable — a spelling that
is not in the table is refused *and* unimplementable at the same time.

### B. Validate after normalization (small, removes a whole class)

Keep the serde aliases, but run the strict check on the **normalized** table
instead of the raw one. After hoisting/flattening and the rename table have run,
only canonical names remain, so the strict lists need only the snake_case
spellings and the section arms shrink by roughly the camel half.

- Removes the "camel in the list but not in the rename table" class outright,
  because the list no longer mentions camel names.
- Smaller blast radius: one call-order change in `frp-core/src/config/file.rs`,
  then delete the camel entries the lists no longer need.
- Risk: error messages change (`unknown field "tcpMux"` today becomes a
  section-scoped complaint, and a hoisted-but-unknown key gets a section-scoped
  message). Some acceptance changes too: a key that is valid inside a section
  but written at the root would now be hoisted and accepted rather than refused —
  arguably correct, but a semantic change that needs the compat suite and a
  deliberate decision, not an accident.

### C. Cross-check the source text (rejected)

Scan the struct files for `alias`/`rename` attributes and diff them against the
strict lists at test time. Rejected as a *substitute*: the exemptions it needs
(legacy keys such as `metadatas`, `subdomain_host`, `tls_trusted_ca_file`, and
pairs that exist for Go parity) recreate exactly the hand-maintained exception
list the plan exists to remove. It is a fine *interim* net while A or B is
being built, but it is not a design.

## Recommendation

Do **B** first, as one reviewable commit, because it deletes the second failure
mode at its root and is small enough to be reasoned about in one sitting. Do
**A** afterwards if B lands clean — A makes the first and third modes
unrepresentable, but it is a 200-row mechanical change that is much easier to
review once the lists are already shortened by B.

Concrete slices, each a separate PR:

1. **B**: strict check after normalization, plus deletion of the camel entries
   that are now handled earlier. Gates: the existing `test_parse_*` family in
   `frp-core/src/config/tests.rs`, the full workspace suite,
   `scripts/tests/docs-go-column.sh` (rows keep their spellings — only the
   validation order moves), and `scripts/compat-test.sh` (a config that parses
   differently for a Go peer is a compat break).
2. **Parity test** on whichever table survives: for every section, every spelling
   the section accepts must be reachable (round-trip through
   `normalize → deserialize`), and every spelling a struct accepts must be
   accepted by strict mode in that section. This is the test that would have
   caught all three failure modes above.
3. **A**, only if 1 and 2 land without a semantic surprise.
4. Update `docs/naming.md` step 3 to the shortened checklist, and delete the
   caveats that slice 1 makes obsolete.

## What this note deliberately does not propose

- A new dependency. Everything here is a table, a rename pass and a test; the
  parser, the serde derive and the strict mode stay as they are.
- Removing Go's camelCase spellings. They are part of the compatibility surface:
  a Go frp config must load unchanged, and `docs/config.md` marks the divergent
  keys on purpose.
- Touching `docs/config.md`'s table structure. Its 18 tables and the Go-column
  suite are the contract that keeps the reference honest; the note only wants
  fewer hands writing to it.

## Open question for the maintainer

Slice 1 changes acceptance in one direction (a section-valid key written at the
root starts working instead of being refused). Is that welcome as a
compatibility improvement, or should the hoist list keep refusing anything the
section list did not name? The answer decides whether slice 1 is a bug fix or a
feature.
