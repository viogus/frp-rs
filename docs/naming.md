# Naming map — one concept, three spellings

frp-rs mirrors Go frp's *wire* and *config* vocabulary, then adds Rust names on
top. That gives most concepts three spellings, and a newcomer who mixes them up
writes code that compiles, passes its own tests and silently loses a value.

This file is the map. For the underlying compatibility rules see
[`developing.md`](developing.md); for the settings themselves see
[`config.md`](config.md).

## The three spellings

| Layer | Spelling | Example | Where it lives |
|---|---|---|---|
| Go config file (compat target) | `camelCase` | `tcpMux = false` | what users write, and what Go frp accepts |
| frp-rs config file | per section | inside `[transport]`: `tcpMux` **or** `tcp_mux`; at the root: `tcpMux` or `tcp_mux` (the camel spelling is hoisted to `tcp_mux`; the snake spelling wins when both are set) | normalised in [`../frp-core/src/config/normalize.rs`](../frp-core/src/config/normalize.rs) |
| Rust field | `snake_case` | `tcp_mux: bool` | config structs in [`../frp-core/src/config/server.rs`](../frp-core/src/config/server.rs) and [`../frp-core/src/config/client.rs`](../frp-core/src/config/client.rs) |
| JSON on the control channel | `snake_case` | `http_user`, `host_header_rewrite` | wire messages in [`../frp-core/src/msg.rs`](../frp-core/src/msg.rs) — **must** stay Go-compatible |

The JSON row is the one with teeth: Go frp *ignores* an unknown key, so a
`camelCase` field on a wire struct is not a compile error and not a test
failure — it is silent data loss on a mixed deployment. Wire structs use
`#[serde(rename)]` only where Go itself is irregular; see the contract test in
[`../frp-core/src/msg.rs`](../frp-core/src/msg.rs).

The config rows are handled by `#[serde(alias = "…")]` on the field.

## Where a config value is read from

Three different mechanisms move a value from the file to the struct, and each
has its own failure mode. Read the one that applies before editing.

1. **Root key, camel or snake** — `#[serde(default = "…")]` plus
   `#[serde(alias = "theGoSpelling")]`. Nothing else needed.
2. **Nested table that Go writes flat** — the client's `[transport.x]`
   sub-tables are *flattened* into root keys by `normalize_client_config`
   ([`../frp-core/src/config/normalize.rs`](../frp-core/src/config/normalize.rs)).
   A key the flatten map does not rename is moved to the root **under its own
   name**, not dropped — where it is then either refused by the root strict list
   or accepted and silently ignored, which is the failure mode to watch for.
3. **Flat key that belongs in a table** — on the server, a few Go-era keys are
   *hoisted* into their table (`[transport]`, `[webServer]`) by
   `normalize_server_config` ([`../frp-core/src/config/normalize.rs`](../frp-core/src/config/normalize.rs)),
   with an explicit `("camelCase", "snake_case")` rename list inside the table.

Order matters, and it differs by side. On the **server** the hoist runs before
the in-table `RENAMES` pass, so a spelling that appears only in `RENAMES` is
never found by the hoist; both spellings must be in the hoist list *and* in
`RENAMES`. On the **client** there is no separate rename pass — the renames are
inline in the flatten map — so the two places are the flatten map and the root
strict list. A spelling missing from either place becomes a silent no-op, and
that is the shape of bug this ordering produces.

Strict mode — on by default — consults **three** different lists, and the one
you must edit depends on where the key lands *after* normalisation:

| Key lands | List | Where |
|---|---|---|
| at the root | `known_server_keys()` / `known_client_keys()` | [`../frp-core/src/config/strict.rs`](../frp-core/src/config/strict.rs) |
| inside a nested section (`[transport]`, `[auth.oidc]`, …) | that section's arm of `section_known_keys` | same file |
| inside an array element (`[[proxies]]`, …) | the corresponding `*KNOWN_KEYS` array | same file |

A field present in the struct but missing from the list it needs is refused as
`unknown field "…" in config file`; a key in the list but not in the struct is
accepted and ignored. Neither mistake is caught by a test unless you write one:
the normalising load path never calls the section check for a root key, and the
drift guard in [`../frp-core/src/config/tests.rs`](../frp-core/src/config/tests.rs)
covers neither the root lists (function-local) nor the section arms (inline
literals). The two sides must be updated together, in the same commit, with a
test that loads the documented spelling.

## Vocabulary

| Term | Means | Not to be confused with |
|---|---|---|
| **control connection** | the long-lived frpc→frps channel: login, heartbeat, proxy/visitor CRUD, V2 messages | the *work* connection — the short-lived one that carries user bytes |
| **work connection** | one TCP (or KCP/QUIC/WS/TLS/yamux) connection per proxied stream | the control connection; also not a *work conn pool* member once in use |
| **proxy** | a named server-side endpoint (`[[proxies]]`): tcp, udp, http, https, stcp, xtcp, tcpmux, sudp | a **plugin**, which is client-side code behind an http/https proxy (`[[httpPlugins]]` on the server side is a different thing again) |
| **visitor** | the client-side dialer for `stcp`/`xtcp`/`sudp` — it asks the server to connect it to a named proxy | a proxy; also not a plugin |
| **bridge** | the data-plane copy between two streams, in [`../frp-core/src/bridge.rs`](../frp-core/src/bridge.rs) | **splice**, the Linux zero-copy fast path in [`../frp-core/src/splice.rs`](../frp-core/src/splice.rs); also not the *relay* naming variant below |
| **relay** | `relay_plain_pooled` and friends — the pooled-buffer bridge entry points, also in [`../frp-core/src/bridge.rs`](../frp-core/src/bridge.rs) | bridge: same concept, different name. **Known wart**, kept to avoid a rename across its nine production call sites |
| **transport** | the `Transport` trait and its implementors (tcp, tls, kcp, quic, websocket, yamux, ssh, aead, pre_read, buffered_read) | **protocol**, which in config means the *carrier* choice (`transport.protocol = "kcp"`) — see the next row |
| **`transport.protocol`** | the config key that selects tcp/kcp/quic/websocket | the `Transport` trait; the name collides with the module, and `[transport] transport = …` is not an accepted key |
| **`tcpMux` / yamux** | one TCP connection carrying many logical streams | `transport.tcpMux` is the switch; yamux is the implementation, vendored under [`../vendor/yamux`](../vendor/yamux) |
| **`IoStream`** | `Box<dyn Transport>` newtype used everywhere a concrete stream type is inconvenient | a transport implementor — it *wraps* one |
| **`PreRead` / `BufferedRead`** | thin wrappers over a raw connection that already consumed a few bytes (protocol sniffing, buffer hand-off) | a general buffered reader; they delegate to the inner stream once drained |
| **`run_id`** | the client instance identifier in the login; reusing it supersedes the older session | a session id |
| **`sk`** (Go: `secretKey`) | the stcp/xtcp secret key; the visitor's copy must match the proxy's | the auth `token`, which is server-wide |
| **`sk_index`** | the server-side index of proxy name → `sk`, used for fallback auth while `proxy_manager.register()` has not returned | a cache; it is a correctness device (see the NewVisitorConn race in [`developing.md`](developing.md)) |

## The one-knob checklist

Adding one user-visible setting touches ten places. Miss one and the setting is
either inert, refused, or documented-but-ignored. Nothing catches a partial
change except the tests named below.

1. Config struct field, `snake_case`, with `#[serde(default = "…")]`.
2. `camelCase` alias, or a rename entry if the value lives in a table.
3. The strict-mode list for where the key lands after normalisation: `known_server_keys()` / `known_client_keys()` for a root key, that section's arm of `section_known_keys` for one inside `[transport]`-style tables, the `*KNOWN_KEYS` array for an array element — both spellings wherever both are accepted.
4. Hoist/flatten entry in [`../frp-core/src/config/normalize.rs`](../frp-core/src/config/normalize.rs).
5. Restart-only bookkeeping in [`../frp-core/src/config/restart_only.rs`](../frp-core/src/config/restart_only.rs) if the value is baked at startup (with the right `ServerReader`).
6. A config test that loads the documented spelling and a strict-mode refusal test (`#[cfg(test)] mod tests` in [`../frp-core/src/config/tests.rs`](../frp-core/src/config/tests.rs)).
7. A row in the table that owns it (Server or Client) in [`config.md`](config.md), with an em dash in the Go column where Go has no equivalent.
8. `ROW_GO_PATHS` plus the `EXPECTED_*` inventory counts (tables, rows, divergent rows, row paths, …) in [`../scripts/tests/docs-go-column.sh`](../scripts/tests/docs-go-column.sh).
9. A `CHANGELOG.md` bullet, and an archive note under `docs/archive/notes/` if the change carries measurements.
10. Regenerate [`../scripts/tests/pathline-cite-expectations.txt`](../scripts/tests/pathline-cite-expectations.txt) and re-pin `guard_data_pin` in [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml).

Steps 9-10 are bookkeeping that costs more than the code: a one-knob change
ends up touching dozens of files, and the cite table alone accounts for most of
the added lines. That is a deliberate trade (line-exact citations survive
refactors badly), and replacing it with symbol anchors is scheduled in
[`refactor-large-modules.md`](refactor-large-modules.md).

## Words to avoid

- **"simple", "just", "obviously"** in comments — the invariant is what matters.
- **"buffer"** alone: say *bridge buffer*, *socket buffer*, *deframer buffer* or
  *pool buffer*. Four different things, four different owners.
- **"timeout"** alone: say *dead link*, *idle timeout*, *dial timeout*,
  *write deadline*, *heartbeat interval*. They fire at different layers.
- **"session"** alone: say *control session* (a login), *KCP session* (a conv),
  *QUIC connection*, *yamux session* (one muxed TCP connection), *visitor
  session* (an stcp tunnel).

## Where to look next

- How the wires fit together: [`architecture.md`](architecture.md).
- How to change something safely: [`developing.md`](developing.md).
- Where to start reading: [`onboarding.md`](onboarding.md).
