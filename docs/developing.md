# Developer Guide

frp-rs is a native Rust implementation of [frp](https://github.com/fatedier/frp), a reverse proxy that exposes services on private networks to the public internet. This guide covers the development workflow for contributors.

Topic map — this guide deliberately does **not** restate the others:

| You want | Go to |
|---|---|
| How the system works (wire protocol, control plane, transports, XTCP) | [architecture.md](architecture.md) |
| Workspace layout, crate responsibilities, project tree | [architecture.md § Overview](architecture.md#overview) |
| Build matrix, feature flags, binary tiers | [CLAUDE.md § Binary Variants](../CLAUDE.md#binary-variants) and [README § Binary Variants](../README.md#binary-variants) |
| Dependency policy (allowed/banned crates) | [CLAUDE.md § Dependency Policy](../CLAUDE.md#dependency-policy-mandatory) |
| Rules, invariants and gotchas an agent must not break | [CLAUDE.md](../CLAUDE.md) |
| Config / proxies / plugins / deployment references | [documentation index](README.md) |
| Historical design docs and audits | [archive/](archive/README.md) |

If this guide states how the code is structured, it must point at the relevant
[architecture.md](architecture.md) section or carry a verified `file:line` (and
the symbol name). The process sections below — build, debug, test, release,
dependency policy — are this document's own domain and need no citation.

## Review protocol (mandatory)

A green gate proves a command exited zero; it does not prove the change does what
its author says. Review is what stands between a plausible diff and a merged one,
and this repository has a single author, so an unreviewed change has no second
reader at all.

**Every change gets at least two independent reviews, and at least one of them is
adversarial.** "Independent" means the reviewer did not write the change — an
author reviewing their own work counts as neither. Both are recorded in the pull
request; an unrecorded review did not happen.

### Reviewer 1 — the claim

Read the diff against the claim in the PR description and ask whether the claim is
*earned*. Concretely:

- **Recompute, do not read.** Every number, count and ratio in the diff or the PR
  is recomputed from its source. If a doc quotes a scenario count, run the thing
  that counts them.
- **Open every citation.** Each `file:line` and each quoted upstream claim is
  opened at that line, in this tree, at this commit. A citation nobody opened is a
  rumour with a line number.
- **Check the evidence class.** A passing unit test is not Go-parity evidence; a
  probe of the real binary or a Go source citation is. See
  [§ What a green test run does and does not prove](#what-a-green-test-run-does-and-does-not-prove).
- **Look for what is missing** as hard as for what is wrong: an untested branch, a
  case named in the description but absent from the tests, a claim with no gate
  behind it.

### Reviewer 2 — adversarial

The adversarial reviewer's brief is to **falsify the change**, not to confirm it.
"Looks good" is not a review. A useful adversarial review tries to construct the
world in which the change is wrong, and reports either the construction or the
attempt:

- **Run the opposite direction.** If the author proved "fails when violated", try
  to make it fail *without* violating the thing it claims to catch — a gate that
  passes because it matches nothing, a test that passes because its assertion is
  unreachable, a check whose pattern silently never fires.
- **Attack the negative case.** Feed the fix the input it does not expect: the
  empty value, the malformed value, both channels at once, the concurrent case,
  the value that is *almost* the one it special-cases.
- **Inspect the diff for weakenings.** Removed assertions, loosened assertions,
  widened timeouts, new `#[allow]`/`#[ignore]`/`#[cfg]`, retries, deleted tests,
  or a claim quietly reworded to match what the code does. Each needs a stated
  reason; "to make CI green" is not one.
- **Check the blast radius.** What else reads the thing that changed? For features,
  what happens when it is *off*? For a shared helper, who else calls it?
- **Say what would change your mind.** If the review cannot state the observation
  that would falsify the change, it is not adversarial.
- **Mutate in your own checkout, never the tree being measured.** If you edit a
  crate under test to build a mutant, do it in a separate worktree and rebuild
  from the restored source before measuring anything else in the shared tree.
  The server integration tests mostly run frps *in-process*, and the rest spawn
  the `target/` frps binary, so in both cases the code under test is whatever was
  compiled into `target/` at build time: a mutant left in a shared tree is
  silently measured as the product by every other agent, and it surfaces as a
  plausible-looking flake in whichever test the mutant happens to break. That is
  worse than no measurement — it is a false positive someone else has to
  disprove, and it looks exactly like a real finding.

### What a review must refuse

Reject, or send back with a question, a change that: has no evidence for its
central claim; substitutes a passing test for the real check the repo uses; adds a
retry or an allow where the cause is unknown; states a number nobody measured;
cites a `file:line` that does not say what it is quoted for; or is described in the
PR more strongly than the diff supports.

### Finding a defect

A review that finds a defect is a success, not a delay — record it. The fix is
re-reviewed (both reviewers), because a fix is a change too and is the most
common place for a second defect to hide. If two reviews disagree, the
disagreement is resolved with evidence, not by seniority or by whichever reading
is more convenient.

### Recording it

The pull request carries a short block, so the next reader can tell what was
actually checked:

```
## Reviews
- Reviewer 1 — method: <how>; checked: <what, with evidence>; findings: <...| none>;
  disposition: <fixed in <sha> | rejected: <reason> | follow-up: <where>>
- Reviewer 2 adversarial — method: <how it tried to falsify>; checked: <claim attacked>;
  findings: <...| none>; disposition: <...>
```

The four fields are the ones rule 4 requires — **method, what was checked,
findings, disposition**. A claim of "reviewed" with no method named is not a
review. Where a review could not check something — a Linux-only path on macOS, a
VPS-only XTCP matrix — it says so, because an unstated gap reads as coverage.
`.github/PULL_REQUEST_TEMPLATE.md` carries the same block.

## 1. Workspace at a glance

Six crates in a layered graph; dependencies flow **upward** (binaries → logic
crates → `frp-core`, which has no internal workspace dependencies). The graph
and the crate-by-crate responsibilities are canonical in
[architecture.md § Overview](architecture.md#overview): `frp-server` /
`frp-client` hold the protocol logic but no `main()`, and the binaries live in
`frps/` and `frpc/`. The annotated module tree is
[§ Project Structure](architecture.md#project-structure).

## 2. Adding a Proxy Type or a Client Plugin

This is the contributor path for a change that adds a new *proxy type* (a new
value for `type`/`proxy_type` that frpc may declare and frps must serve), or a
new *client plugin* (a local-side helper frpc starts before registering a proxy).
It is written for someone who has never opened this repository.

Everything below is grounded in a worked example that was actually walked at
`9b2acefb` and re-derived, cite by cite, at `612f7df1`: a throwaway TCP-like
type called `mytcp` — a client declares
`type = "mytcp"` with `local_ip`/`local_port`/`remote_port`, frps binds a
per-proxy listener and bridges bytes exactly like `tcp`. Where the code silently
accepts a half-done change, the observed behaviour is quoted, because that is
what will happen to you.

Contents:

- [2.1 Reading path](#21-reading-path-what-to-read-and-what-to-skip)
- [2.2 Config parsing and the type allow-lists](#22-config-parsing-and-the-type-allow-lists)
- [2.3 Registration: `ProxyManager` and every site a type appears in](#23-registration-proxymanager-and-every-site-a-type-appears-in)
- [2.4 Listeners and bridging](#24-listeners-and-bridging)
- [2.5 Tests](#25-tests)
- [2.6 The cross-compat scenario](#26-the-cross-compat-scenario)
- [2.7 Reviews and the records you do not own](#27-reviews-and-the-records-you-do-not-own)
- [2.8 Adding a client plugin instead](#28-adding-a-client-plugin-instead)
- [2.9 If you are a new maintainer](#29-if-you-are-a-new-maintainer)

### 2.1 Reading path: what to read, and what to skip

Read in this order. Each step is short and each one removes a class of mistake
from everything after it.

| Order | Read | Why | Can you skip it? |
|---|---|---|---|
| 1 | [`CLAUDE.md`](../CLAUDE.md) § *Development Workflow* and § *Gotchas* | The five mandatory rules (worktree, reviews, compat tests) and the invariants that break Go parity when ignored | No |
| 2 | [architecture.md § Overview](architecture.md#overview) and § [Project Structure](architecture.md#project-structure) | The crate graph: binaries → `frp-server`/`frp-client` → `frp-core`. You cannot tell which crate a change belongs in without it | No |
| 3 | [§ Review protocol](#review-protocol-mandatory) (top of this document) | Two reviews, one adversarial. What a reviewer will ask you for is fixed before you start | No |
| 4 | This section, 2.1 → 2.7, in order | The path itself | No |
| 5 | [§ 5. Testing](#5-testing) — only § *What a green test run does and does not prove* and § *Writing New Tests* | Why a green local test is not Go-parity evidence | The rest of §5 is the CLI/oracle appendix — skip it |
| 6 | [§ 3. Building and Feature Flags](#3-building-and-feature-flags) | Needed the moment your type touches an optional feature | Only if your type adds no `#[cfg]` |

Skip outright, for this task: `docs/history/**` (round-by-round history),
`docs/archive/**`, and [§ 6. Release Process](#6-release-process) — that is the
maintainer path (`2.9`), not the contributor path.

The single most useful habit here is **grep for an existing type and look at every
hit**. Every mechanism a new type touches is a hand-written `match`/`contains`
over type-name string literals; there is no registry, no trait, and no compiler
error when you miss one. Section 2.2 and 2.3 list the sites that exist at
`612f7df1`, but the list is only as good as that commit — re-run the grep.

```bash
# every place a TCP-like type is named, tests included (the list you must walk)
grep -rn '"tcp"' frp-core/src frp-server/src frp-client/src
```

### 2.2 Config parsing and the type allow-lists

**One struct serves every proxy type.** `ProxyConfig` is
`frp-core/src/config/client.rs:674`; there is no per-type config struct and no
per-type parser. All types share the same fields, exactly as Go frp does, so a
type that reuses `local_ip`/`local_port`/`remote_port` needs **no struct change**.
Add a field only for a genuinely new knob, and then follow the house rules:

- `#[serde(default, alias = "camelCaseName")]` so the Go spelling still parses
  (e.g. the `proxyProtocolVersion` alias on `proxy_protocol_version` at
  `frp-core/src/config/client.rs:764`).
- **snake_case on the wire.** `NewProxy`'s JSON keys must stay snake_case
  (`http_user`, `host_header_rewrite`, …). A camelCase wire key is *silently
  ignored* by Go frp — the config is accepted and the setting is dropped. This is
  the single most expensive compatibility bug class in this repository.
- The client plugin config struct is separate: `PluginConfig` at
  `frp-core/src/config/server.rs:1415`.

**The type name itself is validated by an allow-list, and this is the first wall.**
`fn validate_proxy_configs` (`frp-core/src/config/loader.rs:1339`) checks
`p.proxy_type` against `const VALID_PROXY_TYPES` (`frp-core/src/config/loader.rs:1340`).
It is reached only from `fn validate_client_config`
(`frp-core/src/config/loader.rs:1635`); the server path has no equivalent, so a
stray `[[proxies]]` block in `frps.toml` is rejected by the *parser* as
`unknown field "proxies" in config file`, not by this allow-list. Miss the list and
*every* frpc config file using your type fails to load. (The transcripts in §2.2–§2.6
come from a throwaway type walked through this path while it was being written —
none of them describe a type that landed in the tree. Reproduce them with your own
name.) Observed with the real binary before the fix:

```console
$ ./target/debug/frpc -c /tmp/mytcp-bad.toml
/tmp/mytcp-bad.toml: proxy 'throwaway-mytcp': invalid proxy_type 'mytcp'. Valid types: tcp, udp, http, https, stcp, xtcp, sudp, tcpmux
$ echo $?
1
```

Note what that demands of you: the message is a **second, hand-maintained copy of
the list**, inline at `frp-core/src/config/loader.rs:1347`. Adding the name to the
`const` and not to the message leaves the error text lying about what is valid.
Change both, in the same commit.

**Every allow-list you must visit.** Six exist at `612f7df1`, in three crates.
Four sit behind opt-in features a default build does not compile (`admin`, `ssh`,
`dashboard`), which is exactly why they are the easiest to miss. Each one fails
differently:

| # | Site | What it gates | If you skip it |
|---|---|---|---|
| 1 | `const VALID_PROXY_TYPES` — `frp-core/src/config/loader.rs:1340` (+ the message at `frp-core/src/config/loader.rs:1347`), checked by `validate_proxy_configs` at `frp-core/src/config/loader.rs:1339` | frpc config-file load | Fatal at startup: `invalid proxy_type '<type>'` (above). **The first wall, always** |
| 2 | `const VALID_PROXY_TYPES` — `frp-client/src/store.rs:16`, used by `validate_proxy` at `frp-client/src/store.rs:258` | The runtime config store behind the admin API (`/api/store/*`) | Store writes are rejected with `invalid proxy type: <type>`, and an existing store file that contains your type **fails to load** |
| 3 | the seed list in `by_type` — `frp-client/src/admin.rs:391` (feature `admin`) | `/api/proxy/<type>` (Go parity: every known type appears, even empty) | Cosmetic: the endpoint returns no entry for your type |
| 4 | `const VALID_PROXY_TYPES` — `frp-server/src/ssh_gateway.rs:737` (feature `ssh`) | Proxy types accepted over the SSH tunnel gateway | `invalid proxy type: <type>, support types: [tcp http https tcpmux stcp]` |
| 5 | `let valid_types = [...]` — `frp-server/src/dashboard.rs:659`, guard at `:662` (feature `dashboard`) | The dashboard v1 API's per-type endpoint | `404` for your type (a deliberate divergence from Go, which returns an empty list) |
| 6 | `const VALID_TYPES` — `frp-server/src/dashboard.rs:1577`, enforced by `fn validate_type` at `frp-server/src/dashboard.rs:2145` (called at `:2690`; feature `dashboard`) | The dashboard v2 API's `proxy_type` filter | `400 BAD_REQUEST`: `type must be one of tcp, udp, http, https, tcpmux, stcp, xtcp, sudp` (`frp-server/src/dashboard.rs:2151`) |

**The SSH gateway has two gates, not one.** List 4 is only the first: every flag
also carries a scope, matched by `FlagScope::allows`
(`frp-server/src/ssh_gateway.rs:322`) against the `FLAG_SPELLINGS` table
(`frp-server/src/ssh_gateway.rs:361-495`): most base/common flags are
`FlagScope::Any` (every proxy type) and the restricted ones use
`FlagScope::Types`. `remote_port` is scoped to `&["tcp"]`
(`frp-server/src/ssh_gateway.rs:399`), so a Rust-only TCP-like type added to list 4
is *accepted* over SSH but cannot set `remote_port` — the out-of-scope flag is
rejected as `unknown flag: --remote_port` (`frp-server/src/ssh_gateway.rs:189`),
exactly as if Go had never registered it. Add your type to the scope as well as the
allow-list.

Lists 2 through 6 — every one except list 1 — are the ones a Rust↔Rust round-trip
test will not catch. Proven for list 2 with a throwaway unit test against
`validate_proxy`:

```console
thread 'store::tests::throwaway_mytcp_store_accepts' panicked:
mytcp must be an accepted store proxy type: Err(InvalidArgument("invalid proxy type: mytcp"))
```

Two neighbouring lists are **not** on this path, and it is worth knowing why so
you do not hunt them: `const VALID_VISITOR_TYPES` (`frp-client/src/store.rs:19`,
`["stcp", "sudp", "xtcp"]`) enumerates *visitor* types, and `const
FRPC_SUBCOMMANDS` (`frp-core/src/cli.rs:3157`, a `[&str; 12]` pinned in both
directions by the tests beside it) enumerates `frpc <subcommand>` names — it needs
your type only if you are also adding an `frpc <type>` subcommand, which the
minimal path does not.

**There is no server-side allow-list, and that is a trap in the opposite
direction.** `validate_new_proxy` (`frp-server/src/control/proxy_ops/validate.rs:38`)
checks port range, name length/control characters and domain conflicts — it does
**not** check `proxy_type`. So a Rust-only type registers successfully
Rust↔Rust and can never be emitted by Go frpc. If the point of your type is
interoperability, the compat scenario in 2.6 is the only thing that proves it; if
it is a deliberate Rust-only extension, say so explicitly in the PR and in
`docs/architecture.md`, because nothing in the tree will.

### 2.3 Registration: `ProxyManager` and every site a type appears in

The registration call chain is:

```
handle_new_proxy            frp-server/src/control/proxy_ops/mod.rs:1279
  └─ build_proxy_info       frp-server/src/control/proxy_ops/mod.rs:404
  └─ register_proxy_entry   frp-server/src/control/proxy_ops/mod.rs:784
       ├─ register_sk_index frp-server/src/control/proxy_ops/mod.rs:483   (stcp/xtcp/sudp only)
       └─ ProxyManager      frp-server/src/proxy.rs:116
            register / register_or_replace   frp-server/src/proxy.rs:159 / :174
```

`ProxyInfo` is `frp-server/src/proxy.rs:42`; `ProxyManager` holds the live
registry (`remove` at `frp-server/src/proxy.rs:363`).

**Where the port is actually reserved.** `allocate_proxy_port`
(`frp-server/src/control/proxy_ops/mod.rs:161`), called from `handle_new_proxy` at
`frp-server/src/control/proxy_ops/mod.rs:1539`, is the allocator — and it takes
`consumes_port` as an argument:

```rust
if !consumes_port {
    // http/https/tcpmux/stcp/xtcp: no allowPorts consumption. Keep the
    // configured remote_port (usually 0) for display only.
    Ok(remote_port)
} else if is_udp_type { /* dedicated used_udp_ports tracking */ }
else { /* TCP three-phase allocation, probes bindability, inserts used_ports */ }
```

So missing site 5 below is not merely an unenforced check: a type that consumes a
port takes the `!consumes_port` branch and never inserts into `used_ports` /
`used_udp_ports`, so both conflict detection and Go's `portsUsedNum` accounting
are skipped. The port still binds, because site 6 binds it explicitly — which is
exactly why a happy-path test will not tell you.

A caution from this section's own history: the text it replaces said
"`register_proxy_entry` allocates via `allocate_port_multi()`". Open
`allocate_port_multi` (`frp-server/src/proxy.rs:821`) and you will find it
referenced only by its own unit tests at `612f7df1` — it reads like the allocator
from its name and is not one. Open every citation.

**The sites a TCP-like type must appear in.** Six in
`frp-server/src/control/proxy_ops/mod.rs`. Five of them are port accounting; one is
the listener. Read the note after the table before you decide any of them is
optional:

| # | Line | Site | Purpose |
|---|---|---|---|
| 1 | `frp-server/src/control/proxy_ops/mod.rs:660` | `fn proxy_consumes_client_port` | The mirror of the registration increments, shared by the removal path and the sweep |
| 2 | `frp-server/src/control/proxy_ops/mod.rs:811` | `let replaceable = matches!(...)` | Whether re-registering the same name replaces or is rejected |
| 3 | `frp-server/src/control/proxy_ops/mod.rs:842` | the replaced-entry release condition | Releasing the **old** entry's port slot when a replacement lands |
| 4 | `frp-server/src/control/proxy_ops/mod.rs:867` | the `client_ports_used` increment (`*c += 1`, under the guard at `:861`) | Go's `portsUsedNum`; what `max_ports_per_client` counts |
| 5 | `frp-server/src/control/proxy_ops/mod.rs:1374` | `let consumes_port = matches!(...)` in `handle_new_proxy` | The admission check for `max_ports_per_client` |
| 6 | `frp-server/src/control/proxy_ops/mod.rs:1223` | the `tcp` listener branch of `setup_proxy_listeners` | Binds the per-proxy listener. **Load-bearing — see 2.4** |

Do not pattern-match this table blindly; decide by asking what your type *is*.
The neighbouring types show the branches that exist: `register_sk_index`
(`frp-server/src/control/proxy_ops/mod.rs:483`) is for the secret-key routing of
`stcp`/`xtcp`/`sudp`; `VhostManager` (`frp-server/src/vhost.rs:271`) for
`http`/`https` domain routing; `TcpMuxManager` (`frp-server/src/tcpmux.rs:34`)
for `tcpmux`. A type that routes by domain or by secret key belongs in the
corresponding predicate; a type with a real remote port belongs in the port
accounting; a type with a private listener belongs in the listener branch.

Those six are complete for a minimal non-group TCP-like type. A type that can also
join a **TCP** group touches seven more predicate sites across six bullets (the
close handler alone has two) — the group port and its shared listener are owned by
the group, so missing one releases them while a sibling is still live:

- the replacement release in `free_replaced_port`
  (`frp-server/src/control/proxy_ops/mod.rs:577`);
- the join check in `handle_new_proxy`
  (`frp-server/src/control/proxy_ops/mod.rs:1458-1459`);
- the `unregister_control` sweep (`frp-server/src/control/proxy_ops/mod.rs:2451-2452`);
- the close handler `handle_close_proxy`, both its membership check
  (`frp-server/src/control/proxy.rs:79-80`) and its port snapshot
  (`frp-server/src/control/proxy.rs:108-109`);
- the dashboard delete path, `cleanup_deleted_proxy_port`
  (`frp-server/src/dashboard.rs:1138-1139`);
- the TCP-group load-balance filter in the pool dispatch path
  (`frp-server/src/control/pool.rs:702`, in `handle_proxy_user_conn`).

Those are the **tcp**-group sites; HTTP/HTTPS and TCPMux group members route
through their own, separate predicates. The `kind_https` line at
`frp-server/src/control/proxy.rs:154` is inside the HTTP-group branch
(`is_http_group_member`, `frp-server/src/control/proxy.rs:85`) and is **not** a
tcp-group site; the TCPMux equivalent is `frp-server/src/control/proxy.rs:96`.

**How much of that the round-trip test actually pins: one site.** Reverting site
6 alone makes the test fail; reverting all five accounting sites (1–5) together
still passes. Measured, in the worked example:

```
# listener branch reverted (site 6):
mytcp remote port 55559 never became reachable: Connection refused (os error 61)
test result: FAILED. 0 passed; 1 failed

# all five accounting sites reverted (1-5), listener branch restored:
test result: ok. 1 passed; 0 failed
```

So the port accounting has **no test coverage** for a new type and will not be
caught by the obvious end-to-end test. Either add the targeted tests described in
2.5, or state in the PR that the sites were changed by inspection —
and expect the adversarial reviewer to ask which of the six you can show failing
without the change.

### 2.4 Listeners and bridging

**There are no listener traits.** This surprises people, so it is worth being
literal: there is no `trait Listener` in `frp-server/src` or `frp-core/src`.
Listeners are plain `tokio::spawn` tasks. The TCP accept loop is
`listen_and_proxy` (`frp-server/src/control/proxy_ops/mod.rs:2211`):

```rust
pub(crate) async fn listen_and_proxy(
    listener: TcpListener,
    port: u16,
    proxy_name: String,
    internal_tx: mpsc::Sender<InternalMsg>,
    tcp_keepalive: i64,
    user_conn_sem: Option<Arc<tokio::sync::Semaphore>>,
)
```

Its accept path applies `set_nodelay`/`set_keepalive`, takes the per-proxy
user-conn permit, then sends `InternalMsg::ProxyUserConn`
(`frp-server/src/state.rs:344`) — which carries `proxy_name`, `user_conn`,
`pre_read`, `user_conn_permit` and `group_selected`. The task's `JoinHandle` is
stored in `ControlState::listener_handles` under the proxy name; UDP listeners
keep their socket in `AppState::udp_sockets`. That is the whole lifecycle: spawn,
register the handle, drop the handle to stop it.

`setup_proxy_listeners` (`frp-server/src/control/proxy_ops/mod.rs:886`) is where a
type chooses its shape, and the shape is a raw `if`/`else if` chain, not a list of
peer branches. It has three *type* branches, a group branch, and a fall-through:

- `udp` / `sudp` (`frp-server/src/control/proxy_ops/mod.rs:914`) — bind an
  `Arc<UdpSocket>` and pull work connections with
  `InternalMsg::UdpNeedsWorkConn`; SUDP reuses the socket on `EADDRINUSE`.
- the `is_nat_hole` predicate — `stcp`/`xtcp`/`tcpmux`
  (`frp-server/src/control/proxy_ops/mod.rs:900-901`, branch at `:1018`) — no remote
  port and no per-proxy listener; STCP/XTCP visitors connect back over a work
  connection, and TCPMux routes by `HTTP CONNECT` host
  (`frp-server/src/tcpmux.rs:34`).
- `tcp` (`frp-server/src/control/proxy_ops/mod.rs:1223`, after the group branch at
  `:1020`) — bind a per-proxy `TcpListener` via `bind_tcp_proxy_with_retry`, then
  spawn `listen_and_proxy` and record the handle. **Your TCP-like type goes here.**
- the `} else {` fall-through (`frp-server/src/control/proxy_ops/mod.rs:1257`) —
  everything else, including `http` and `https`. There is no per-proxy listener:
  the shared VHost listener routes by host/domain
  (`frp-server/src/vhost.rs:271`).

Note the asymmetry: `http`/`https` are *not* a branch of their own, they fall
through. A type that forgets to add itself lands here rather than hitting an `else`
that could have rejected it.

**The listener site fails silently, and this is the trap worth internalising.**
There is no `else` that errors. The fall-through branch
(`frp-server/src/control/proxy_ops/mod.rs:1262`) logs:

```
"{} proxy '{}' registered (shared listener, port {})"
```

Registration then *succeeds* — the server logs a normal success line, the
`NewProxyResp` carries no error, and the client prints:

```console
$ grep 'registered' /tmp/g3-trapdir/frps.log
... frp_server::control::proxy_ops: mytcp proxy 'throwaway-mytcp' registered (shared listener, port 37202)
$ grep 'registered' /tmp/g3-trapdir/frpc.log
... frp_client::service: Proxy 'throwaway-mytcp' registered on remote port :37202
```

Nothing listens on 37202. A user connection is refused:

```
TRAP: proxy_port_reachable=no
```

If you remember one thing from this section: **a missed listener branch produces a
green registration and a dead port.** The only guard is the end-to-end test in
2.5.

**Bridging needs no new code for a TCP-like type.** Once the user connection
reaches the control handler as `InternalMsg::ProxyUserConn`, the existing path
pops a work connection, sends `StartWorkConn`, and pumps bytes.
`assign_work_to_proxy` (`frp-server/src/control/bridge.rs:3117`) prepares the
assignment and `run_work_bridge` (`frp-server/src/control/bridge.rs:2430`) selects
plain vs encrypted/compressed. Add code there only if your type rewrites the
stream (host headers, protocol framing). On the client side, registration builds
the wire message in `create_new_proxy_msg` (`frp-client/src/proxy.rs:94`) and the
work-connection side lives in `frp-client/src/work_conn.rs`.

**One client-side detail that will cost you an hour if nobody says it.** Build a
`ProxyConfig` by hand (in a test, or in code) and `enabled` is **`false`**:

```rust
// frp-core/src/config/client.rs:768
#[serde(default = "default_true")]
pub enabled: bool,
```

The serde default only applies to *deserialization*. A derived `Default` — i.e.
`..Default::default()` — leaves it `false`, and `filter_active_proxies`
(`frp-client/src/service.rs:5055`) ends with `active.retain(|p| p.enabled)`. The
proxy is then never registered at all. There is no error: the client logs in,
pools work connections, and the only symptom is `Connection refused` on the
remote port. Set `enabled: true` explicitly in every hand-built `ProxyConfig`.

### 2.5 Tests

**Unit test — pin the allow-list you changed.** The config gate is the first wall;
give it a test next to the existing ones in `frp-core/src/config/tests.rs`. Call
the loader bare, not as `frp_core::config::…`: the file starts with
`use super::*;` (`frp-core/src/config/tests.rs:3`), and inside the crate its own
name is not a valid path prefix. `load_client_config_from_str` is defined at
`frp-core/src/config/loader.rs:176`:

```rust
#[test]
fn mytcp_config_parses() {
    let toml = r#"
server_addr = "127.0.0.1"
server_port = 7000
[[proxies]]
name = "p"
type = "mytcp"
local_ip = "127.0.0.1"
local_port = 8080
remote_port = 7001
"#;
    let cfg = load_client_config_from_str(toml).unwrap();
    assert_eq!(cfg.proxies[0].proxy_type, "mytcp");
}
```

Run it on its own first:

```bash
cargo test -j 2 -p frp-core --lib mytcp_config_parses -- --nocapture
```

Add the mirrored cases for each allow-list you touched — for the store, that is a
`validate_proxy` test in `frp-client/src/store.rs` (see the observed failure text
in 2.2).

**End-to-end — the test that actually proves the listener.** The in-process client
harness is `frp-client/tests/common/mod.rs`. It builds a full
`ClientService` + `ServerService` pair with an echo server; `new_inner`
(`frp-client/tests/common/mod.rs:235`) hard-codes `proxy_type: "tcp"`, so **either
add a constructor that takes a proxy type, or build the config explicitly in your
test file**. Note that the harness's own `ProxyConfig` literal sets
`enabled: true` explicitly (`frp-client/tests/common/mod.rs:302`) — that is not
decoration, see 2.4. The shape that worked — this is the whole file, copy-pasteable:

```rust
// frp-client/tests/mytcp_throwaway.rs   (throwaway while walking the path)
mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{allocate_port, init_tracing, start_echo_server, start_frps, wait_for_port};
use frp_client::service::Service as ClientService;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn mytcp_round_trip() {
    init_tracing(); // frp-client/tests/common/mod.rs:15
    let echo_port = allocate_port(); // :38
    let server_port = allocate_port();
    let proxy_port = allocate_port();

    let _echo = start_echo_server(echo_port); // :87 — sync, returns a JoinHandle
    let _server = start_frps(server_port, "test-token").await; // :153 — async, JoinHandle
    wait_for_port(
        SocketAddr::from(([127, 0, 0, 1], server_port)),
        Duration::from_secs(5),
    ) // :183
    .await
    .expect("server did not start");

    let cfg = frp_core::config::ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: "test-token".into(),
        login_fail_exit: false,
        pool_count: 2,
        tcp_mux: false,
        tls_enable: false,
        proxies: vec![frp_core::config::ProxyConfig {
            name: "mytcp-e2e".into(),
            proxy_type: "mytcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: echo_port,
            remote_port: proxy_port,
            enabled: true, // see 2.4 — `..Default::default()` here means "never registered"
            ..Default::default()
        }],
        ..Default::default()
    };

    // `Service::new` builds the client; `run()` drives it until the task is dropped.
    let client = ClientService::new(cfg, None).await.expect("create client");
    let _client = tokio::spawn(async move {
        let _ = client.run().await;
    });

    // Registration is asynchronous: poll the remote port until something accepts.
    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(proxy_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    const PAYLOAD: &[u8] = b"mytcp round trip\n";
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("mytcp remote port never became reachable");
    stream.write_all(PAYLOAD).await.unwrap();
    let mut buf = vec![0u8; PAYLOAD.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, &PAYLOAD[..]);
}
```

```bash
# No build step: `start_frps` boots frps in-process (`frp-client/tests/common/mod.rs:172`),
# so this test needs no frps/frpc binary on disk at all.
cargo test -j 2 -p frp-client --test mytcp_throwaway -- --nocapture
```

For a server-side test that speaks the raw V1 protocol, the harness is
`frp-server/tests/common/mod.rs`: `register_tcp_proxy`, `open_tcp_proxy_bridge`
and `pump_tcp_bridge` (`frp-server/tests/common/mod.rs:22`, `:81`, `:135`) drive
the control channel and the work connection directly, and `start_test_server`
(`:387`) boots frps in-process. Use it when the interesting behaviour is in
registration, not in the client.

**What you must add, and what review will ask for.** The round-trip test proves
the listener and nothing else (2.3). For a type that consumes a client port, the
reviewable package is:

1. the config-gate unit test (above), and its mirror for every allow-list touched;
2. the end-to-end round trip through the real `ClientService`;
3. a test that the port accounting fires — e.g. with `max_ports_per_client = 1`,
   two proxies of your type must have the second rejected; and a close/re-register
   test that the slot is released;
4. a statement of which of the six sites in 2.3 are covered and which are
   inspection-only. An unstated gap reads as coverage — that is the finding the
   adversarial reviewer is told to look for.

The integration-test crates are `frp-core/tests/`, `frp-server/tests/` and
`frp-client/tests/`; unit tests are inline `#[cfg(test)] mod tests` in the same
file as the code. Run the crate you touched, plus the config crate whatever you
touched:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -D warnings
cargo test -j 2 -p frp-core
cargo test -j 2 -p frp-server
cargo test -j 2 -p frp-client
```

### 2.6 The cross-compat scenario

The unit and integration suites pin **frp-rs's own** behaviour. They cannot show
Go compatibility; only `scripts/compat-test.sh` against a real Go binary can (see
[§ What a green test run does and does not prove](#what-a-green-test-run-does-and-does-not-prove)).
There are two cases, and they are not the same amount of work:

- **Your type exists in Go frp** — then it needs a `go-to-rust` (or `rust-to-go`)
  scenario in `scripts/compat-test.sh`, and the scenario must actually run.
- **Your type is a Rust-only extension** — the normal case for a type you invent,
  because Go frpc's config decoder rejects the name before it ever dials. Do
  **not** write a `go-to-rust` scenario for it. Measured, verbatim, against the Go
  frp v0.71.0 binary:

  ```console
  $ frpc -c frpc.toml       # [[proxies]] type = "revtcp"  (Rust-only type)
  decode proxy at index 0: unknown proxy type: revtcp
  $ echo $?
  1
  ```

  What you add instead is a **Rust↔Rust** scenario in the same runner
  (`test_kcp_rust_to_rust`, `scripts/compat-test.sh:5319`, is the existing
  template). It still drives the real `frps` and `frpc` binaries and the real wire
  protocol, and it is what a reviewer will ask for. Say in the PR that compat with
  Go frpc is *not applicable* rather than leaving the section empty.

**What the harness gives you, and what it does not.** `write_frps_config`
(`scripts/compat-test.sh:1065`) is type-agnostic. `write_frpc_config`
(`scripts/compat-test.sh:1128`) is **not**: it hard-codes `type = "tcp"` in both
the Go (`:1169`) and the Rust (`:1197`) branch, so a new type cannot reuse it. Either
add a `type` parameter to the writer **and** update every existing caller, or write
the frpc TOML inline in your scenario the way the special-case scenarios do.
Inline is usually the smaller diff and the one to prefer.

**Prerequisites — and the one that costs an hour if nobody says it.** Before any
selector runs, the runner checks (a) that all four binaries exist and are
executable — `GO_FRPS`, `GO_FRPC`, `$PROJECT_DIR/target/release/frps`,
`$PROJECT_DIR/target/release/frpc` (`scripts/compat-test.sh:5299-5305`), and
(b) that `frp-core/tests/certs/` holds `ca.crt`, `server.crt` and `server.key`
(`:96`, checked at `:5307-5313`). Three consequences:

- The Rust paths are **hard-coded to `target/release/`**
  (`scripts/compat-test.sh:94-95`) and are not environment-overridable. A debug
  build does not satisfy them, so build release before running *any* selector,
  including the Rust↔Rust one:
  ```bash
  cargo build --release -j 2 -p frps -p frpc
  ```
  This is the only build §2.6 needs; the in-process test in §2.5 needs none.
- The Go pair must be present even for a Rust↔Rust scenario, because the preflight
  checks all four paths. `scripts/download-go-frp.sh` fetches it (`--go-version`
  overrides the default `0.71.0`).
- The certs are checked for every scenario, TLS-less ones included.

Add your scenario function beside the existing ones and register it with the other
`run_test` lines at the bottom of the file (`run_test test_g2r_tcp_plain` is at
`scripts/compat-test.sh:5935`). This is the Rust↔Rust shape:

```bash
test_r2r_mytcp_plain() {
    local name="rust-to-rust-mytcp-plain"        # the DISPLAY name
    should_run_test "$name" || return 0
    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2r-mytcp"
    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Rust frps: write_frps_config is type-agnostic.
    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # write_frpc_config hard-codes type = "tcp" (Go :817, Rust :845), so write the
    # Rust frpc TOML inline. Mirror its `rust` branch: snake_case keys. A camelCase
    # key is silently dropped by frp-core and the run fails for the wrong reason.
    cat > "$TEST_DIR/$name/frpc.toml" <<EOF
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
login_fail_exit = true
pool_count = 1
tls_enable = false

[[proxies]]
name = "mytcp-compat"
type = "mytcp"
local_ip = "127.0.0.1"
local_port = $echo_port
remote_port = $proxy_port
EOF
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    wait_for_port_safe 127.0.0.1 "$proxy_port" 10 || {
        fail_test "$name" "proxy port not reachable"
        return
    }
    local result
    result=$(send_and_expect "$proxy_port" "hello-mytcp" "hello-mytcp" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "expected OK: got $result"
    fi
}

# ...at the bottom of the file, with the other registrations:
run_test test_r2r_mytcp_plain
```

One config trap worth repeating, because it fails with an unreadable error:
`tcp_mux` must agree on both sides. The `rust` branch of `write_frps_config`
writes `tcp_mux = false`, so the inline client config must too — the working
spelling is the snake_case `tcp_mux` of the Rust `write_frpc_config` branch
(`scripts/compat-test.sh:1128-1204`). What *is* dropped, silently, is the **top-level**
camelCase key: `tcpMux = false` written at the top level is accepted by the
config parser whether or not a `[transport]` table is present, but it has no serde
alias on `tcp_mux` (`frp-core/src/config/client.rs:321-322`), so the client keeps the default
`tcp_mux = true` and the server rejects the first frame with `invalid V1 msg
length: 144116287587483648 (max: 10240), raw header: 000200010000000000`. A plain
mismatch — server `tcp_mux = false`, client snake_case `tcp_mux = true` — fails
identically. Do not generalise the drop to every camelCase key: `transport.tcpMux`
under a `[transport]` table is **not** dropped — `normalize_client_config`
(`frp-core/src/config/normalize.rs:1172`, called from
`frp-core/src/config/loader.rs:186`) flattens `[transport]` and maps
`"tcpMux" => "tcp_mux"` (`frp-core/src/config/normalize.rs:1446`), so that
spelling logs in and registers fine.

Helper line numbers for orientation: `start_echo_server`
`scripts/compat-test.sh:484`, `send_and_expect` `:511`, `log` `:867`,
`should_run_test` `:906`. `run_go` (`:327`) is only for the Go-driving scenarios;
a Rust↔Rust scenario invokes `"$RUST_FRPS"` / `"$RUST_FRPC"` directly, as above.

**What a passing run prints.** Use the display name and paste the `N passed` line
into the PR:

```console
$ bash scripts/compat-test.sh --test rust-to-rust-mytcp-plain
...
[LOG] === rust-to-rust-mytcp-plain ===
[PASS] rust-to-rust-mytcp-plain
...
 RESULTS: 1 passed, 0 failed

All tests passed!
$ echo $?
0
```

**`--test` takes the display name; `--list` prints the function name. They do not
match, and the mismatch exits 0.** `should_run_test`
(`scripts/compat-test.sh:906`) compares the selector against the `local name=`
inside the function, while `--list` (`scripts/compat-test.sh:168`) prints the
function names:

```console
$ bash scripts/compat-test.sh --list | grep mytcp
test_r2r_mytcp_plain
$ bash scripts/compat-test.sh --test test_r2r_mytcp_plain     # WRONG: function name
 RESULTS: 0 passed, 0 failed

All tests passed!
$ echo $?
0
```

Every scenario returns early on a selector miss and the summary counts only what
ran, so a wrong name is a **silent false green**, not an error. Use the display
name, and always confirm the count is at least 1:

```bash
bash scripts/compat-test.sh --test rust-to-rust-mytcp-plain --verbose
```

**CI lanes that must see it.** There is no per-scenario list to update —
`compat.yml` runs the whole script on every push and pull request, so a new
`run_test` line is picked up automatically. What you must check instead:

- `.github/workflows/compat.yml:56` builds frps/frpc with
  `--features "ssh,quic,dashboard"`. A scenario that needs another feature will
  fail in CI while passing locally (or silently skip). Extend that build line, or
  gate the scenario, and say which in the PR.
- `.github/workflows/ci.yml` — `Verify (bench + feature sets)` checks
  `cargo check --workspace --no-default-features --features tiny` and
  `--features micro`. If your type touches an optional feature, the workspace must
  still compile in both tiers, which normally means `#[cfg]`-gating your code.
  `Tests (unit)`, `Tests (server integration)` and `Tests (client integration)`
  run the suites in 2.5; a test file left ungated is checked by all of them.
- `.github/workflows/xtcp-compat.yml` runs the XTCP pairwise matrix daily on a
  VPS. Only relevant if your type uses NAT traversal.
- A change to the transport or the wire protocol — not just a proxy type — also
  owes a row in `scripts/protocol-matrix.sh`; run
  `bash scripts/protocol-matrix.sh` locally.

### 2.7 Reviews and the records you do not own

The rules are in [§ Review protocol](#review-protocol-mandatory) at the top of
this document: **two independent reviews, at least one adversarial, recorded in
the PR**. This repository has a single author, so "I wrote it and it passes" is
the status quo the rule exists to break. There is no reviewer to inherit — you
have to recruit one. The record goes in the `## Reviews` block of
`.github/PULL_REQUEST_TEMPLATE.md`, which asks for exactly four fields per
reviewer:

```
- Reviewer 1 — method: ; checked: ; findings: ; disposition:
- Reviewer 2 adversarial — method: ; checked: ; findings: ; disposition:
```

`method` is how the review was done, `checked` is what with what evidence,
`findings` is what it turned up, `disposition` is what was done about it. A
record left as an empty template has no review.

For a new proxy type specifically, the evidence a reviewer will demand is the
artefact list in 2.5 plus the statements below. Write them **in the PR**, not in
the code:

- the grep you ran, and the sites you decided were not applicable, with the
  reason (2.3);
- which of the six allow-lists you changed, and the observed failure text for
  each before the change — the failure text is the evidence that the site mattered;
- that the end-to-end test passes **and** what it does not cover (the port
  accounting, 2.3);
- for a compat scenario, the `--test <display-name>` command and its
  `N passed` line, not just "compat passes";
- whether the type is intended to be reachable from Go frpc, and if not, that it
  is a deliberate Rust-only extension (2.2).

**Three files you do not edit.** `TODO.md`, `CHANGELOG.md` and
`docs/history/development-log.md` are owned by the coordinator: the backlog item,
the user-facing release note, and the round record respectively. A contributor's
diff does not touch them; propose the wording in the PR instead. (`CLAUDE.md` is
likewise not a contributor file — it holds rules, not history.)

### 2.8 Adding a client plugin instead

A *client plugin* is the local-side helper frpc starts to serve a proxy's
`local_port` — `http_proxy`, `socks5`, `static_file`, `tls2raw`, the
`http2http`/`https2http` family, and so on. Prefer this when the new capability is
about *how a local service is spoken to*, not about a new server-side routing
mechanism.

The surface is much smaller than a proxy type's, and unlike a proxy type it has
**no config allow-list at all**:

- `dispatch_plugin_start` (`frp-client/src/plugin/mod.rs:276`) is the only
  dispatcher. It matches `plugin_cfg.plugin_type.as_str()` and returns
  `Err(frp_core::Error::Config("unknown plugin type: <name>"))` for anything it
  does not know — at *runtime*, when frpc starts the plugin, not at config load.
- Add `frp-client/src/plugin/<name>.rs`, declare it with `mod <name>;` and a
  `pub(crate) use` in `frp-client/src/plugin/mod.rs`, and add the match arm.
- A plugin returns `PluginHandle` (`frp-client/src/plugin/mod.rs`) — a
  `local_addr`, the task's `JoinHandle`, and a shutdown sender. Existing plugins
  in `frp-client/src/plugin/` are the templates; pick the closest one
  (`socks5.rs` for a protocol speaker, `static_file.rs` for a trivial one).
- `frp-client/src/service.rs:1073` starts plugins for `p.plugin`. `virtual_net`
  is special-cased there because its work connections go to the shared vnet
  controller in `frp-client/src/work_conn.rs`.
- Server-side plugins are a **different** surface: `frp-server/src/plugin/mod.rs`
  with `frp-server/src/plugin/http.rs` implements the `[[httpPlugins]]` manager
  (feature `http-proxy`). Do not confuse the two when grepping.

Path to write for a plugin: a unit test for the plugin's own logic, an entry in
the client integration suite (`frp-client/tests/`), and — if the plugin is
observable through a proxy type — a compat scenario per 2.6. The review evidence
in 2.7 applies unchanged.

### 2.9 If you are a new maintainer

The release path is [§ 6. Release Process](#6-release-process): a pre-release
checklist, the mandatory version alignment (frp-rs's version *is* the Go frp
version it tracks — currently `0.71.0`; `frp-vnet` is the documented exception),
and `bash scripts/repo-health.sh` as the local mirror of the `health` CI job.
Run `bash scripts/repo-health.sh` before you trust any number in the docs: the
countable figures are generated, the doc-figure gate covers only an enumerated
list of claim wordings, and a count restated in new words is not caught. If your
prose quotes a tracked figure, re-run the script and keep the figure true.

**The known bus-factor limits, stated plainly.** This repository has one human
author. The controls that substitute for a second person are:

- the two-review rule in [§ Review protocol](#review-protocol-mandatory) — which
  requires a *second agent*, not a second look by you;
- the pre-release checklist item for vendored crates (`vendor/rustls`,
  `vendor/yamux`, `vendor/russh` under `[patch.crates-io]`), which no tool covers
  because `cargo update` will not pick up upstream security releases for a patched
  crate — that checklist line **is** the control;
- `scripts/compat-test.sh` against a real Go binary, which is the only evidence of
  Go parity.

Two things are deliberately not gated, and you must therefore check them by hand:
client-plugin wiring, and fuzz-target enablement (a `#[cfg]`-disabled target reads
the same as a live one to a text gate). `scripts/compat-test.sh` exercises
neither — do not cite it for them. The open backlog for these and the rest of the
known debt is `TODO.md`; the bus-factor item is the one this section answers.

## 3. Building and Feature Flags

### Quick Reference

```bash
cargo build                  # Debug build (all crates)
cargo build --release        # Release build (opt-level=z, LTO, panic=abort)
cargo test --workspace       # Run all tests
cargo clippy                 # Lint
```

### Toolchain pinning

`rust-toolchain.toml` at the repo root pins the compiler for every rustup-based
job that builds the checked-out tree: an exact `channel` (`X.Y.Z`, never `stable`
and never a floating `X.Y`), `profile = "minimal"`, and the `clippy`/`rustfmt`
components. That is what makes a `cargo fmt` / `cargo clippy` result a property
of the commit rather than of the runner image or a developer's `rustup default`.

The channel is exact because a floating one re-introduces the failure the pin
removes: a new rustc/clippy release can add a lint that fires on untouched code,
which turns the lint gate red on a commit that changed nothing. An exact version
makes a compiler bump a deliberate, reviewable diff.

It is the file, not a workflow step, that selects the compiler: any `rustc`,
`cargo`, `cargo clippy` or `cargo fmt` run anywhere under the repository resolves
it, including subdirectories such as `scripts/frp-stress/`. A job therefore only
has to make sure the toolchain exists — run `rustup toolchain install --no-self-update`
in the repository. With no toolchain argument it installs exactly what the file
asks for: the pinned version, its `profile`, and its two components, reporting
`the active toolchain ... has been installed` and `overridden by
<repo>/rust-toolchain.toml`. A missing toolchain is never a reason to pass
`+toolchain` by hand. Bare `rustup show` also auto-installs the file's
toolchain, but rustup 1.29.1 warns that auto-installation is deprecated, so the
explicit install is what CI runs.

Typo behaviour, measured on rustup 1.29.1. A **misspelled component** is loud
where it matters: with a fresh `RUSTUP_HOME` — the state a CI runner starts in —
`rustup toolchain install --no-self-update` fails with `error: component 'rustfm'
for target '<host>' is unavailable for download for channel '1.98.1-<host>'`,
exit 1, installing nothing; only when that toolchain is **already installed**
does it degrade to `warn: skipping unavailable component rustfm` with exit 0, so
a local typo of that kind can pass unnoticed. An **unknown key** in the
`[toolchain]` table (for example `profilee = "minimal"`, or `component = [...]`
instead of `components`) is ignored with no warning at all and exits 0 in both
cases, so **that** typo rests on review. A typo in a *value* is always loud (a
malformed file, an unknown `profile` and a non-existent `channel` all exit 1),
and no silent case can leave the compiler unpinned: the `channel` rustup actually
resolves is the one the assertion step in `ci.yml` checks. And the file must keep
the standard `[toolchain]` section form:
rustup also honours an inline table (`toolchain = { channel = "..." }`) and a
dotted key (`toolchain.channel = "..."`), but the `repo-health.sh` gate parses
the section form only and **fails closed** on those two spellings rather than
accepting a form it does not check.

**Covered by construction:** the Docker source build. `docker/Dockerfile.source`
copies `rust-toolchain.toml` into the build context **before** it installs the
toolchain and the musl target (`WORKDIR /build` → `COPY rust-toolchain.toml ./` →
`RUN rustup toolchain install --no-self-update` → assertion →
`RUN rustup target add $(cat /tmp/rust_target)`), so an image built from it uses
the pinned compiler even though the base tag still floats. The assertion exists
because the base image's own default toolchain is *not* the pin: it fails the
build when the active toolchain is not the file's channel, or when the
environment overrode it (`RUSTUP_TOOLCHAIN`), both measured. `scripts/repo-health.sh`'s
gate still scans `.github/workflows/` only; this file is covered by its own
assertion.

To bump:

1. edit `channel` in `rust-toolchain.toml` to the new exact version;
2. run `rustup toolchain install --no-self-update` — it installs the new
   toolchain and its two components;
3. run `cargo fmt --all -- --check`;
4. run `cargo clippy --workspace --all-targets --all-features -- -D warnings`;
5. fix every lint the new compiler reports **in the same PR**. That diff is the
   point of the pin: it is the reviewable consequence of the bump, not a
   follow-up chore.

`scripts/repo-health.sh` gates the pin itself: exactly one toolchain file, at the
repo root, in `.toml` form (tracked, present, and not shadowed by an untracked
one); an exact `channel` inside its `[toolchain]` table, quoted either way and
tolerating a trailing TOML comment; no `toolchain:` input on a
`setup-rust-toolchain` step — with the step recognised in these forms and no
others: inline `- uses: ...`, `uses :`, a quoted `uses:` value, a named step
(`- name: ...` with `uses:` on its own line, or under a bare `-`), and the flow
form `- {uses: ..., with: {...}}`, in `*.yml` and `*.yaml` — and the key
recognised as a block mapping, a flow mapping, a comma-separated flow mapping,
or a single-/double-quoted key, matched case-insensitively since action input
names are reported to be matched that way; and no floating `rustup default`
selection under `.github/workflows/`. Each of those checks' own comments list the
known shapes it does **not** see (each measured there, and explicitly not a
completeness claim): for the `toolchain:` scan those are, among others, an anchor
or tag token between `-` and `uses:`, a flow sequence with no `-` line, a comment
at or below the step's indentation before the key, a `#` inside an earlier quoted
value on the same line, an anchor/alias on the `with:` block, a key consumed by a
different action, and a case-different action URL (not verified against GitHub) —
plus fail-closed over-catches, where a `{`/`,` inside a quoted scalar or inline
comment, a nested sequence in the step, or a key-like line inside a block scalar
makes the gate fail a workflow that never passes the input. Deliberately not
chased: the check is a text scan, not a YAML parser.

### Binary Variants

Four size tiers via feature flags. The authoritative tier list, exact commands
and measured binary sizes live in the README —
[**Binary Variants**](../README.md#binary-variants). The resulting binaries are
named `frps`/`frpc` (default/full), `frps-tiny`/`frpc-tiny`, and
`frps-micro`/`frpc-micro`.

CI compiles the tiny and micro tiers with `RUSTFLAGS="-D warnings"` (the
`verify` job in `.github/workflows/ci.yml`). Two workspace checks cover the
tier **library and binary** graphs:

```bash
RUSTFLAGS="-D warnings" cargo check --workspace --no-default-features --features tiny
RUSTFLAGS="-D warnings" cargo check --workspace --no-default-features --features micro
```

They deliberately omit `--all-targets`. On a `--workspace` invocation every
member is a root, so the dev-dependency edges enter the graph, and
`frp-server`'s dev-dependency on `frp-client` (`frp-server/Cargo.toml:67`,
default features) plus `frp-client`'s on `frp-server` re-enable both crates'
`default` sets — measured, the micro graph flips from `frp-client = []` to
`frp-client = [chacha20, compression, default, http2http, kcp, oidc, quic,
tcp-mux, tls, websocket]`, and `frp-server` from `[]` to
`[chacha20, compression, default, http-proxy, kcp, oidc, quic, ssh, tcp-mux,
tls, websocket]`.
`--all-targets` there would therefore drop the tier coverage for those two
crates, not extend it.

The tier **test** targets are compiled by five sibling isolated checks instead,
where `-p` makes the crate the only root and the dev-dependency edge cannot
reopen its defaults:

```bash
RUSTFLAGS="-D warnings" cargo check -p frp-client --no-default-features --all-targets
RUSTFLAGS="-D warnings" cargo check -p frp-client --no-default-features --features tls,tcp-mux --all-targets
RUSTFLAGS="-D warnings" cargo check -p frp-server --no-default-features --all-targets
RUSTFLAGS="-D warnings" cargo check -p frp-server --no-default-features --features tls,http-proxy,tcp-mux --all-targets
RUSTFLAGS="-D warnings" cargo check -p frp-core   --no-default-features --all-targets
```

The `frp-core` step was added after the first two. `frp-core` is the only root
there, so its own features are off — measured with `cargo check -p frp-core
--no-default-features --all-targets -v`, every `frp-core` rustc invocation in
that run (the lib, the lib test, all 10 `frp-core/tests/*.rs` targets, and the
`frp-core/benches/crypto_bridge.rs` bench) carries zero `--cfg feature=` flags.
`frp-core`'s dev-dependencies are all external crates
(`frp-core/Cargo.toml`), none of which can depend back on it, so
no dev-dependency edge re-enables a feature of the crate under test. The run
exits 0; before the gates landed it exited 101 with four failing units (lib test,
`kcp`, `xtcp_p2p`, `protocol_round14`). It checks the same property as its two
siblings: a feature-gated item referenced without its gate is a compile error —
or, under `-D warnings`, a `dead_code` / `unused_imports` / `unused_mut` error.

Measured bound on the `frp-core` step, the same bound as the other two: it
covers the code that is *compiled*, not the targets. 6 of `frp-core`'s 10 test
targets are whole-file-cfg'd *empty* here — `kcp.rs` and `xtcp_p2p.rs` (`kcp`),
`mux.rs` and `yamux_rst.rs` (`tcp-mux`), `xtcp_quic_sni.rs` (`tls`),
`ws_tls_stall.rs` (`tls` + `websocket`). `cargo test -p frp-core
--no-default-features --test <t> -- --list` reports 0 tests for each, versus
4/12/13/3/2/1 with default features. The other 4 targets — `config_round14.rs`
(2 tests), `protocol_round14.rs` (4), `proxy_auth.rs` (3),
`v2_handshake_round14.rs` (3) — are compiled and checked in full.

That step is compile-only: it type-checks the test targets but does not link or
run them, so it cannot see a missing `#[cfg]` on a test or bench that still
*compiles*. The runtime half lives in the test lanes: `Tests (unit)` runs the
no-features command for `frp-core` and for `frp-client`, and
`Tests (server integration)` runs it for `frp-server`; the two sibling steps are
spelled out below. For `frp-core`, in the same no-features configuration:

```bash
cargo test -p frp-core --no-default-features --all-targets
```

Measured: it exits 0 with 609 tests passed / 0 failed and 124 criterion bench
cases run (default features: 903 tests / 130 bench cases; `--all-features`: 917 /
130). It is the only gate for the two `frp-core` failures of that class found
here: eight lib tests failed with `"compression not compiled"` (597 passed / 8
failed), and `frp-core/benches/crypto_bridge.rs` panicked the bench binary at
registration time — `thread 'main' panicked at
frp-core/benches/crypto_bridge.rs:60:64: called `Result::unwrap()` on an `Err`
value: "compression not compiled"`. Wall clock, macOS arm64: 5.39 s / 5.42 s /
5.51 s warm on three runs, and 19.84 s with `frp-core`'s lib, its 10 test targets
and the bench touched (forced rebuild). The runner's cost — Linux, cold cache —
was not measured.

Both `frp-core` steps inherit the same bound: neither checks nor runs anything
inside the 6 whole-file-cfg'd *empty* test targets listed in the paragraph above
(each reports 0 tests in this configuration — `cargo test -p frp-core
--no-default-features --test <t> -- --list` reports 0, and the runtime step's
output shows `running 0 tests`). They differ in what they do with the
code that is present — the `verify` step type-checks it, the unit-lane step links
and runs it. Neither *executes* the compression criterion group: the runtime step
does run the bench binary (measured `Running benches/crypto_bridge.rs`, 124
criterion cases), but the group's body is `#[cfg(feature = "compression")]`-gated,
so it is absent in the no-features configuration; the `verify` lane compiles the
group with default features (`cargo bench --workspace --no-run`) but runs no
benchmark. The
`--all-targets` flag drops the doctest target, which for `frp-core` contains 2
tests and both are `ignore`-marked (`frp-core/src/buffer_pool.rs:54`,
`frp-core/src/feature_gate.rs:9`), so nothing is lost.

The same runtime class was live in the sibling crates and now has two sibling
runtime steps.

`frp-client`'s is in the `Tests (unit)` lane, because its test targets need no
`frps`/`frpc` binary — they drive in-process services:

```bash
cargo test -p frp-client --no-default-features --all-targets -j 1 --no-fail-fast
```

`frp-server`'s is in the `Tests (server integration)` lane, because its five
`oidc_integration.rs` tests spawn `frps` and fail environmentally without one
(`failed to start frps: Os { code: 2, kind: NotFound }`,
`frp-server/tests/common/mod.rs`); that lane already builds the binary and sets
`FRPS_BIN`/`FRPC_BIN`:

```bash
cargo test -p frp-server --no-default-features --all-targets -j 1 --no-fail-fast
```

What they close, measured in this worktree (macOS arm64): 34 deterministic
`frp-server` failures and one `frp-client` failure in the no-features
configuration, all of them a missing `#[cfg]`. Per target, with the feature
floor each gate needs (every passing run below enables that feature and nothing
else) — `frp-server/tests/http_plugin.rs` (23 tests) and `http_plugin_ping.rs`
(5) whole-file on `http-proxy`;
`control::proxy_ops::unregister_generation_tests::stale_unregister_keeps_fresh_user_record`
on `http-proxy`; `test_login_via_websocket` on `websocket` and
`test_login_via_tls` on `tls` in `server_protocol.rs`; the two TLS cases in
`slowloris.rs` on `tls`; the three e2e cases in `vhost_https_sni.rs` on `tls`
(its fourth case, `test_hello_construction_extracts_sni`, needs no feature and
still runs in the no-features configuration);
`test_e2e_tcp_proxy_over_websocket` in `frp-client/tests/end_to_end.rs` on
`websocket` — 7 tests with the feature, 6 without, so no case is lost. The gates
are on each crate's **own** features, not `frp-core`'s: measured with `-v`,
`frp-core` is compiled with `websocket`, `tls` and the rest **on** in both graphs
(frp-server's dev-dependency on frp-client supplies frp-client's default
features, which forward `frp-core/websocket`, `frp-core/tls`, …), so
`TransportProtocol::WebSocket` exists and parses there.

Measured after the gates: `frp-server`'s step exited 0 with 436 passed /
0 failed in three of five samples, with an `frps` binary present (2m08s warm);
the other two were 435 passed / 1 failed on the pre-existing
`test_tcpmux_proxy_auth_interior_space_rejected_407` flake, since fixed (it has
its own `TODO.md` entry); it also failed with default features and was the only
measured pre-existing failure in those five samples. Without an `frps` binary
the same command adds 5 environmental
`oidc_integration` failures — that is why it is not in the unit lane.
`frp-client`'s step exits 101 **on this macOS host** with 312-313 passed
and 1-2 failed, both failures not this class and recorded in
[`../TODO.md`](../TODO.md) (a `start_paused` deadline flake and a
filename-containing-`0xFF` `EILSEQ`); both also run in the existing
default-features `Tests (client integration)` lane.

Neither step was measured on the runner (Linux, cache restored from a
default-feature build), and neither says anything about the whole-file-cfg'd
*empty* targets listed below — 9 of `frp-server`'s 35 `tests/*.rs`, 6 of
`frp-core`'s 10, 4 of `frp-client`'s 40 — which compile to nothing in this
configuration and so cannot fail in it.

This is the **no-features** configuration for frp-client — the micro tier — not the
tiny one. frp-client's tiny set is `tls,tcp-mux`, and it has its own isolated check
(the `frp-client` tiny-targets step above). That step exists because
`plugin_h2.rs` was gated on `tls` alone while its `h2`/`http` imports come from
`http2http` — so in tiny it was selected in and failed to compile (5 errors). It
is now gated on `http2http`; see [`../TODO.md`](../TODO.md).

That run compiles frp-client's test targets with `tls` off, which is what makes
a missing gate fail: the 5 `tls`-gated items in the
`frp-client/src/plugin/mod.rs` test module (four tests plus the
`plugin_peer_ip_now` helper) and the `tls`-gated import plus two tests in
`frp-client/tests/plugin_http.rs` reference tls-only items, so dropping their
`#[cfg(feature = "tls")]` turns those references into compile errors (or an
unused import) under `-D warnings`. With the gates present they are excluded
and the run is clean — the `tls`-on path of the same tests is compiled by the
`Lint` lane's `--all-targets --all-features` clippy.

The frp-server sibling compiles `frp-server`'s test targets with **frp-server's
own features at the micro set — none of `tls`, `websocket`, `ssh`, `kcp`,
`quic`, `oidc`, `http-proxy`, `compression`, `chacha20`, `tcp-mux`**. For the
targets that are compiled, every `#[cfg(feature = ...)]` in `frp-server`'s lib
and test targets is complete for that configuration: an optional item referenced
without its gate is a compile error (or an unused import) under `-D warnings`
here instead of a warning nothing promotes.

Measured bound on that guarantee — it is a bound on the **code that is compiled**,
not on the targets. A whole-file-cfg'd target compiles to nothing, and inside a
target that does compile, any `#[cfg]`-excluded item is unchecked in exactly the
same way. Concretely: **9 of `frp-server`'s 35 `tests/*.rs` targets are
whole-file-cfg'd *empty* in this configuration**, so nothing inside them is
checked at all — `dashboard_integration.rs` and `dashboard_v2_integration.rs`
(`dashboard`), `ssh_gateway.rs` (`ssh`), `transport_e2e_kcp.rs` (`kcp`),
`transport_e2e_quic.rs` and `v2_quic_r2r.rs` (`quic`), `vhost_h2c.rs` and the
pair this change gated, `http_plugin.rs` and `http_plugin_ping.rs`
(`http-proxy`). `cargo test
-p frp-server --no-default-features --test <t> -- --list` reports 0 tests for
each of the nine. The same escape exists item-by-item inside a target that does
compile: `vhost_audit_fixes.rs` declares 21 tests, 2 of them `tls`-gated per
item, so 19 are compiled and checked and those 2 are not. `mock_oidc.rs` also
reports 0 tests but is not one of the nine: it has no inner `#[cfg]`, so it is
not whole-file-cfg'd empty — it is compiled as its own test target and simply
declares no tests.

What it does **not** prove, and why it is still meaningful: `frp-core` in that
graph is compiled with *most* of its features, not with them off.
`frp-server`'s dev-dependency on `frp-client` (default features,
`frp-server/Cargo.toml`) pulls `frp-client`'s `default` set in, and that
forwards `frp-core/websocket`, `frp-core/tls`, and the rest — measured,
`frp-core`'s enabled set in that graph is exactly

```
chacha20 compression http-client kcp oidc quic stun tcp-mux tls websocket
```

ten features; six further features are off (`vnet`, `admin-auth`,
`mem-profile`, `profiling`, `debug-logs`, `otel`), `default` aside — `default`
itself is not activated either, since both `frp-server` and `frp-client` depend
on `frp-core` with `default-features = false`. So `frp-core` can hand
`frp-server` a type, variant or function that frp-server's matching feature does
not know about. That mismatch is exactly what this step exercises:
`ConnectionType::WebSocket` exists in `frp-core` regardless of frp-server's
feature set (it is deliberately **not** feature-gated — see the doc comment on
the variant in `frp-core/src/transport/mod.rs`), so
`frp-server/src/service.rs`'s `match` has an unconditional arm whose body is
gated per feature. Before that fix the run failed with `error[E0004]` —
non-exhaustive patterns, `ConnectionType::WebSocket` not covered.

Why this broke on `websocket` and not on the other nine features `frp-core` has
on: `websocket` is the only `frp-core` feature that gated a variant of
`ConnectionType` — before this change the `WebSocket` variant was the only
`#[cfg]`-gated item inside that enum. The other features on in this graph
(`tls`, `kcp`, `quic`, `oidc`, `compression`, `chacha20`, `tcp-mux`,
`http-client`, `stun`) disagree with frp-server's empty set just as much, but
none of them changes the shape of `ConnectionType`, so none of them can make a
`match` **on `ConnectionType`** non-exhaustive. That is why the fix belongs on
the type — the variant now always exists, so exhaustiveness of `ConnectionType`
matches no longer depends on the two crates' feature sets agreeing.

**That guarantee is scoped to `ConnectionType` and is not a systematic property
of the workspace.** `oidc` — one of the nine features named just above — has a
live sibling of exactly this class: `AuthMethod::Oidc` is gated in `frp-core`
and matched in `frp-server`, so
`cargo check -p frp-server --no-default-features --features dashboard --all-targets`
still fails with `E0004` at `frp-server/src/dashboard.rs:2352`. [`../TODO.md`](../TODO.md)
records it; the fix here was per-variant, not a guarantee that no other
feature-gated variant exists.

The step therefore checks frp-server's **own** gates, not frp-core's: a missing
`#[cfg(feature = "tls")]` on a tls-only item in frp-server is caught, while
frp-core's feature-off configuration is not compiled by this step at all (the
`-p frp-core` step above is what covers frp-core's test targets with its own
features off; the two `--workspace` tier checks cover frp-core's lib and the
tier binaries in a genuinely small graph). The two TLS-driving cases in
`frp-server/tests/vhost_audit_fixes.rs`
and the whole of `frp-server/tests/vhost_h2c.rs` carry `#[cfg(feature = "tls")]`
/ `#![cfg(feature = "http-proxy")]` respectively, so the rest of the first file
stays compiled — and therefore checked — with `tls` off; the `tls`-on path of
all of them is compiled by the `Lint` lane's `--all-targets --all-features`
clippy. `frp-server`'s tier library graph is also covered by the two workspace
checks above.

### Feature Flags

The authoritative flag table — every feature, the crate it belongs to, what it
removes, which are default-ON, and which are opt-in/dev-only — is
[**CLAUDE.md § Binary Variants**](../CLAUDE.md#binary-variants). It is not
duplicated here.

Which crates are vendored (and why, and when each can be dropped) is in
[**README § Vendored crates**](../README.md#vendored-crates).

### Release Profile

```toml
# Cargo.toml
[profile.release]
opt-level = "z"       # Optimize for size
lto = "fat"           # Link-time optimization across all crates
codegen-units = 1     # Single codegen unit for better optimization
strip = "symbols"     # Strip debug symbols
panic = "abort"       # Abort on panic (smaller binary, no unwind tables)
```

After `cargo build --release`, further compress with UPX:

```bash
upx --best --lzma target/release/frps target/release/frpc
```

## 4. Debugging

### RUST_LOG Levels

The project uses `tracing` for structured logging. Available levels: `error`, `warn`, `info`, `debug`, `trace`.

```bash
# Debug logging for everything
RUST_LOG=debug cargo run --bin frps -- -c frps.toml

# Target-specific logging
RUST_LOG=frp_server::control=debug cargo run --bin frps -- -c frps.toml

# Trace-level for wire protocol inspection
RUST_LOG=frp_core::protocol=trace cargo run --bin frps -- -c frps.toml

# Multiple targets
RUST_LOG=frp_server=debug,frp_core::protocol=trace cargo run --bin frps -- -c frps.toml
```

Key tracing targets:
- `frp_core::protocol` -- V1 frame writes (`trace` level includes full JSON payloads)
- `frp_server::service` -- connection accept, TLS handshake, dispatch
- `frp_server::control` -- control handler lifecycle, internal message routing, heartbeat
- `frp_server::control::bridge` -- work connection bridging
- `frp_core::transport` -- connection type detection, magic byte stripping
- `frp_server::nathole` -- NAT hole punch session lifecycle
- `frp_client::service` -- client lifecycle, proxy registration
- `frp_client::work_conn` -- work connection management

### Inspecting Wire Protocol

Enable trace-level logging for `frp_core::protocol` to see every frame sent and received:

```bash
RUST_LOG=frp_core::protocol=trace cargo run --bin frps -- -c frps.toml
```

This outputs the type byte, payload length, and full JSON content for each V1 frame. For hex dumps of the raw bytes, use an external tool like `tcpdump` or `wireshark`:

```bash
# Capture frp traffic on loopback
sudo tcpdump -i lo -A -s 0 port 7000

# Capture with hex dump
sudo tcpdump -i lo -X -s 0 port 7000
```

### Common Issues

**"Connection reset by peer" on startup:**
- Check that `bind_port` is not already in use
- Verify the server and client `token` match
- Check that `server_addr` is reachable from the client

**Proxy connections time out:**
- Check `heartbeat_timeout` -- client must ping within this interval
- Check `pool_count` -- if too low, proxy connections queue and expire after 10s
- Verify firewall allows traffic on proxy ports

**Enrypted bridge corruption:**
- Both sides must agree on `use_encryption` and `use_compression`
- The encryption key derives from the auth token -- mismatched tokens = corrupted bridge

**TLS handshake failures:**
- TLS requires valid cert/key files (`tls_cert_file`, `tls_key_file`)
- When `tls_only` is true, non-TLS connections are rejected
- WebSocket over TLS requires the client to connect with `wss://` and `transport_protocol = "wss"`

**XTCP hole punch failures:**
- Both provider and visitor need public internet access for STUN
- Symmetric NAT on both sides usually prevents hole punching -- STCP fallback is needed
- Check that `sk` is set and identical on both provider and visitor proxies

## 5. Testing

### What a green test run does and does not prove

Read this before quoting a test count as evidence of compatibility. It is the
single easiest mistake to make in this repository.

**Hard evidence — these compare frp-rs against a real Go frp binary:**

| Gate | What it establishes |
|---|---|
| `scripts/compat-test.sh` — 86 scenarios + 17 XTCP pairwise, vs Go frp v0.71.0 | Wire and behavioural parity with the reference implementation |
| `scripts/protocol-matrix.sh` — 11 transport rows | Data actually moves through frps+frpc for every transport / encryption / mux combination |
| Daily `xtcp-compat.yml` on a VPS | XTCP hole punching against Go frpc across a real NAT |

Every count in that table is re-measured from the scripts by `bash
scripts/repo-health.sh` (it prints each claim next to the source that produces
it) — the figures are cross-checked, not remembered.

**Proxy evidence — the unit and integration tests (`repo-health.sh` counts the
in-tree test functions; the number that *pass* is a runtime fact):**

They pin *frp-rs's own* behaviour. That is genuinely valuable (they catch
regressions, and most were written by reading Go's source), but a passing suite
does **not** establish Go parity, because a test encodes the author's *model* of
Go's behaviour — and that model can be wrong.

This is not hypothetical. The project's own history records it, repeatedly:

- **Round 4**: "the slowloris ponging test was RED — the round-3 claim was
  wrong". The test assumed yamux's ping frame tag was `4`; it is `2`. A whole
  round's confidence rested on a test that was failing.
- **Round 16**: the round-15 suite "encoded a **FALSE `SplitHostPort` claim**".
  All three oracles in `vhost.rs` and `vhost_h2c.rs` had to be flipped once Go's
  `net/ipsock.go:216` was actually read.
- **Round 16**: "two round-14/15-era tests that pinned the trim behaviour [were]
  flipped".
- **Round 6**: a stale pin in `server_protocol.rs:101` — a target-only test run
  was blind to the integration file that held the real expectation.
- **Round 7**: a round-9-era "established reject policy" pin turned out to rest
  on a false premise; the expectation was flipped after probing the real
  Go 1.25.12 binary.
- **Round 9** returned a verdict of "production code healthy, **test
  completeness below standard**" while **1253 tests were green**.
- **Round 9** also surfaced that the shared test fixture kept
  `authentication_timeout = 0`, so replay protection — the thing under test —
  was never exercised at all.

**A caveat about the hard evidence itself.** The compat gate is the strongest
evidence available here, but it is not perfectly reliable *as a signal*: on
2026-09-17 the `compat` CI job failed **2 of 3 consecutive runs on the same
commit**, with **different** scenarios each time (`go-to-rust-quic:
FAIL:CONNECT_TIMEOUT`, then `tcp-tls`/`tcp-tls-mux` zero throughput and `ws-plain`
proxy port unreachable), and passed on the third. The diff under test could not
have been responsible — its only compiled change was inside a
`#[cfg(not(target_os = "linux"))]` block, absent from Linux CI entirely.

So: a **red** compat run should be re-run before it is believed, and a **green**
one is strong but not absolute. Flakiness in the one gate the project treats as
authoritative is a defect in its own right — see [`../TODO.md`](../TODO.md).
A flaky test is a bug in the test's timing assumptions, not a re-run button:
fix it (per-invocation names, a retry bounded to the specific transient, the
original assertion kept) instead of learning to ignore it.

The harness now absorbs that class instead of failing on it.
`scripts/compat-test.sh` re-drives a scenario **once** (`FRP_COMPAT_RETRY_MAX`,
default `1`; `0` disables it; a non-numeric value, or one above the hard cap `5`
once leading zeros are stripped — `(( ))` would read a padded value as octal —
is refused with rc 2) when — and only when — every failure the attempt recorded
was a readiness gate: a prose reason carrying ` port` before a trailing
`not reachable` / `not listening`, or ending in `did not start`, or a
`FAIL:CONNECT_TIMEOUT` / `FAIL:TIMEOUT` verdict, bare, labelled or wrapped in a
longer reason. A reason carrying `FAIL:MISMATCH` or `FAIL:CONNECT_RESPONSE` is
refused first, wherever it sits — so a `FAIL:MISMATCH` whose payload merely
quotes "not reachable" is never re-driven, even when it arrives beside a genuine
timeout from another proxy: that verdict is a *deterministic* answer from a live
peer, and re-running it would only turn a real protocol regression into a coin
flip. The re-drive starts from a clean slate (the attempt's servers reaped, its
scratch directory removed) and re-asserts the whole scenario, so a deterministic
failure fails the second attempt too and is reported once. A green run that
leaned on the re-drive says so: `[RETRY]` at the scenario and `RETRIED:` in the
summary. The classification, the bound and the bookkeeping are driven in the
`health` job by `scripts/tests/compat-scenario-retry.sh`, because none of them is
visible from a green run. **This is a bounded recovery, not an identified
cause**: the named subset was looped 210 times on an idle host with no flake
reproduced, so what is established is that a run no longer fails on the
readiness class — nothing about *why* a listener is late, and nothing that closes
the compat-gate item.

**The practical rules:**

1. A green suite means "no *known* regression", not "compatible with Go frp".
2. Before claiming a compatibility fix, cite Go source (`file:line`) or a probe
   of the real binary — not a passing test.
3. When a test expectation is the *only* thing asserting a behaviour, say so.
   That is a hypothesis, not evidence.
4. For a parity claim, prefer adding a `compat-test.sh` scenario over another
   unit test.

### Unit Tests

Unit tests live inline in `#[cfg(test)] mod tests` blocks within source files. Integration tests live in the `frp-server/tests/` and `frp-client/tests/` directories (see "Writing New Tests" below).

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p frp-core
cargo test -p frp-server
cargo test -p frp-client

# Run a specific test by name
cargo test -p frp-core -- protocol::tests

# Run with output (show println! and tracing)
cargo test -- --nocapture

# Run ignored tests (e.g., tests requiring network access)
cargo test -- --ignored
```

### Cross-Compatibility Tests

The compat test suite verifies Go frp <-> Rust frp interop across all proxy types and transport protocols:

```bash
# Full suite (86 run_test scenarios, 7 of which are gated on Go frp V2)
bash scripts/compat-test.sh --verbose

# Filter by proxy type and direction
bash scripts/compat-test.sh tcp g2r     # TCP proxy, Go client -> Rust server
bash scripts/compat-test.sh xtcp        # All XTCP tests
bash scripts/compat-test.sh transport   # Transport protocol tests only

# Filter by direction
bash scripts/compat-test.sh g2r         # All Go->Rust tests
bash scripts/compat-test.sh r2g         # All Rust->Go tests
```

The compat tests require Go frp binaries. Download them first:

```bash
bash scripts/download-go-frp.sh
```

This downloads Go frp v0.71.0 binaries to `/tmp/frp_<version>_<os>_<arch>/` (for
example `/tmp/frp_0.71.0_linux_amd64/`) — that is where `compat-test.sh` looks for
them. Override the location with `GO_FRP_DIR=/path/to/dir`. The CI gate is
`.github/workflows/compat.yml`.

> Do **not** commit the downloaded Go binaries. They are platform- and
> version-specific and a stale copy is worse than none: `scripts/go-frp/` used to
> hold v0.69.1 macOS x86_64 binaries while the project targeted v0.71.0, and any
> size/memory comparison against them was meaningless. (For scale, the v0.71.0 Go
> binaries measured 17.7 MB (`frps`) / 14.2 MB (`frpc`) — see the generated table
> in [`../README.md`](../README.md#technical-differences-vs-go-frp), reproduced by
> `scripts/compare-go-frp.sh`.) Use
> [`scripts/compare-go-frp.sh`](../scripts/compare-go-frp.sh), which verifies
> platform and version before it compares anything.

### XTCP CI Tests

XTCP tests require public internet (for STUN) and run on a VPS:

```bash
# Setup VPS (one-time)
bash scripts/vps-setup.sh

# Run XTCP tests on VPS
bash scripts/remote-frps.sh xtcp
```

XTCP CI uses sharded matrix jobs (`.github/workflows/xtcp-compat.yml`) with per-shard directories for isolation. 17 tests covering the 2x2 implementation matrix (Go/Rust server × Go/Rust client) plus QUIC-data-plane and encrypted variants.

### Writing New Tests

Follow these conventions:

1. **Inline tests**: add to the relevant source file's `#[cfg(test)] mod tests`
2. **Integration tests**: add to `frp-server/tests/` or `frp-client/tests/`
3. **Use `test_utils`**: each crate may provide test helpers for spawning servers/clients
4. **Avoid port conflicts**: use port `0` for auto-allocation or pick unique ports
5. **Clean up**: ensure spawned tasks/processes are killed on test completion
6. **Wait on a deadline, not an attempt count**: a readiness/retry loop should poll against a wall-clock deadline (`Instant::now() + timeout`) rather than a fixed `for _ in 0..N` plus sleep — the attempt count is a hidden, load-dependent time budget that flakes on CI — and it must report the last error on exhaustion, not a bare `expect`.

### The `dashboard` lane: build ordering (read this before running it)

`frp-server`'s dashboard tests spawn the real `frps` binary that
`common::frps_binary()` resolves — `FRPS_BIN` in CI, else `CARGO_BIN_EXE_frps`,
else `../frps`, else `../target/<profile>/frps`. **That artifact has to be the
dashboard build, and nothing else in the workspace keeps it that way.** A build
of the `frps` bin from the crate's default features writes `target/debug/frps`
again **without** the dashboard: any invocation of `cargo test -p frps` — its
test targets link the binary through `CARGO_BIN_EXE_frps`, so **even
`-- --list` does it** (measured: `1 → 0` in 0.167 s) — and a plain
`cargo build -p frps`, even one cargo treats as a no-op (measured: `1 → 0` in a
0.16 s cached build). A clippy run is *not* a cause:
`touch frps/src/main.rs && cargo clippy -p frps --all-targets --all-features`
left the artifact byte-identical (same size and mtime). Run the lane in this
order:

```bash
cargo build -p frps --features dashboard
cargo test  -p frp-server --features dashboard -j 1
```

Getting the order wrong used to be silent. On the **pre-fix tree** (`97a8d7e`)
the lane reported `0 passed; 20 failed` after **45.6 s**, every failure
`frps dashboard_port not ready: "port N not ready after 15s"`, and the run left
**17 `frps` children at `PPID 1`** still `LISTEN` on their ports (20 listeners;
the three `CapturedFrps`-based tests in the same run reaped theirs — the orphan
count grew by 0 for them). The artifact itself flips between the two runs:
`grep -ac "Dashboard listening on" target/debug/frps` is 1 right after the
dashboard build and 0 after `cargo test -p frps`, and the same marker through
`strings target/debug/frps | grep -c "Dashboard listening on"` is 2 → 0 (the two
hits are the plain and the TLS format string — same conclusion, different count,
so name the tool).

On the **fixed** head the same swapped artifact fails fast and says why:
`0 passed; 20 failed`, every failure the guard's own message, `finished in
1.58 s` (8.5 s wall, that run including the compile of the edited test target),
and **0 children** left. The guard is what fires first, not the 15 s timeouts;
it is compiled only in a `dashboard`-enabled test target and scans the artifact
`frps_binary()` resolved (see the doc comment there). Both halves are pinned by
`frp-server/tests/frps_binary_guard.rs` (the panic *message*) and
`frp-server/tests/frps_handle_orphan.rs` (a panicking `FrpsHandle::start` kills
the child it spawned). The CI lane that reads this ordering is the
`Tests (server integration)` job in `.github/workflows/ci.yml`, whose
`cargo build --bin frps --features dashboard` step immediately precedes its
`cargo test -p frp-server --features dashboard -j 1` step.

The guard is compiled **only** when the test target has the `dashboard` feature
(`#[cfg(feature = "dashboard")]`): the no-features runtime step in that same CI
job resolves the same `FRPS_BIN` for tests that need no dashboard, so it must
not require the listener. The check costs one `read` and byte scan of the
resolved artifact (measured 28.83 ms for the 81,444,248-byte dashboard
artifact), cached per test-binary process.

### Benchmarks

Criterion micro-benchmarks in `frp-core/benches/crypto_bridge.rs` (8 groups) and `frp-server/benches/nathole.rs` (2 groups):

```bash
# Run all benchmarks (slow — runs each bench many times)
cargo bench -p frp-core
cargo bench -p frp-server

# Quick compile-time check (used in CI)
cargo bench --workspace --no-run

# Run specific groups
cargo bench -p frp-core -- protocol_all_types
cargo bench -p frp-core -- bridge
cargo bench -p frp-server -- nat_analysis
```

CI gate: `cargo bench --workspace --no-run` in `.github/workflows/ci.yml` ensures benchmarks don't bit-rot.

### Stress Tests

Long-running load test (`scripts/stress-test.sh`) that runs frps + frpc under connection churn:

```bash
bash scripts/stress-test.sh
```

Monitors memory, connection counts, and throughput. Runs weekly in CI via `.github/workflows/stress-test.yml`. The `scripts/frp-stress/` crate contains the load generator (not part of the main workspace).

### Property & Fuzz Tests

Proptest-based tests verify correctness under adversarial inputs:
- **Config normalization** (`frp-core/src/config/tests.rs`): proptest blocks covering idempotency, flat↔nested equivalence, camelCase→snake_case
- **Protocol fuzzing** (`frp-core/src/protocol.rs`): all 256 V1 type bytes × arbitrary payloads, V2 arbitrary type IDs, truncated frames, magic detection

> Raw test counts are deliberately **not** curated: adding a test would otherwise
> fail the `health` job, and the workspace total was observed to differ between
> environments on the *same* tree (215/2069 locally vs 216/2071 in CI, PR #353 —
> cause not established). The `Tests` section of `bash scripts/repo-health.sh`
> prints `test functions`, `files with tests`, `frp-server/tests` and
> `proptest blocks`; per-file counts are read from the tree when needed. Fuzz
> *targets* are not curated either — a text grep cannot tell a live target from
> a `#[cfg]`-disabled one — so their count and enablement are covered by the test
> suite, not by the gate.

### CLI exit codes (`frpc` / `frps`)

The CLI contract is Go's **on the config/flag-failure surface**: exit 0 on
success, exit 1 on a failure the command detects and reports through its own
error path. The qualifiers are measured and listed below, not rhetorical — Go
itself exits 2 when frps panics on an oidc config with no issuer, and it does not
exit at all on a tokenless token config (it starts and runs), while frp-rs keeps
three codes of its own (`2`/`3`/`4`): `2` only for a `--config-dir` refusal
(a surface Go answers with 0, or has no flag for at all), and `3`/`4` for
service-construction failures — including some like `auth.tokenSource` and
`[store]` that Go *has* and refuses with 1, and some like the empty-token check
that Go does not refuse at all. There is no per-class scheme to preserve, and
`EXIT_CONFIG`/2 no longer covers a single-config or `verify` failure.

**Decision (2026-09-27): `3`/`4` stay, and the kind that picks them is now a
typed value, not a substring match.** The subclass item `TODO.md:5290` names the
line that does not support the claim it makes — a substring match picks the
`3`/`4` codes — and `TODO.md:3366` carries the same round's measured
`--strict-config` table; both were filed against this change. The argument, in
the order the alternatives were weighed:

- **Collapsing `3`/`4` into Go's `1` would not have removed a compatibility
  risk, because there is none to remove.** Go's CLI is 0-or-nonzero, and every
  frp-rs construction failure already returns nonzero. A collapsing change would
  delete a documented, tested distinction (`auth.tokenSource` → 3, `[store]` → 4)
  that costs a Go-compatible caller nothing — nobody matches `1` *specifically*
  and breaks on 3 — while the widening path (Go later inventing exit codes) is
  not one frp-rs can pre-empt.
- **What the codes buy is the only per-class signal on this surface**, and it is
  the one an operator wants: "the auth material could not be resolved" versus
  "the service could not be constructed for another reason". `EXIT_CONFIG`/2 is
  already kept on exactly that reasoning (a surface Go answers with 0), so this is
  the repository's existing posture, not a new one.
- **The one thing that was *not* defensible was how the code was chosen**, and
  that is what changed: `logging::is_token_error` (`msg.contains("token") ||
  msg.contains("auth")`) read the *formatted* error, which embeds the config path
  and any URL from the config. It has been deleted; the constructor tags the
  failure with `frp_core::init_error::InitErrorKind` at the point it is raised,
  and the daemons read only that tag (`e.kind().exit_code()`).

The kind → code mapping, which is now the whole contract:

| `InitErrorKind` | code | what it covers | measured input (Go v0.71.0 → frp-rs) |
|---|---|---|---|
| `Auth` | **3** | auth material cannot be resolved or validated, or an auth method is refused | `frpc`/`frps` `auth.tokenSource` → missing file: Go **1** → frp-rs **3** |
| `Other` | **4** | any other construction failure (currently the client `[store]` source) | `frpc` `[store] path` → non-JSON file: Go **1** → frp-rs **4**, for *either* file name |

The mapping is asserted literally in `frp-core/src/init_error.rs`
(`kind_maps_to_the_documented_exit_code`), and **the displayed text has no path
to it**: there is no callable substring classifier left in `frp-core`
(`logging::is_token_error` is gone), and the daemons' three arms match on the
kind.

Measured 2026-09-26 against Go frp **v0.71.0** (darwin/arm64) and the frp-rs
`frpc`/`frps` binaries, with one unknown top-level key added to an otherwise
valid config (plus the variations named):

| command | Go v0.71.0 | frp-rs (now) |
|---|---|---|
| `frpc -c bad.toml` (unknown key) | 1 | 1 |
| `frpc -c missing.toml` / `-c <dir>` / `-c badport.toml` | 1 | 1 |
| `frpc --strict-config=foo -c good.toml` | 1 | 1 (message differs) |
| `frpc verify -c bad.toml` (and missing / bad port) | 1 | 1 |
| `frpc verify -c good.toml` | 0 | 0 |
| `frpc reload\|status\|stop -c bad.toml` | 1 | 1 |
| `frps -c badfrps.toml` (and missing / dir / bad port) | 1 | 1 |
| `frpc` with `[auth] tokenSource` → a missing file | 1 (0.26 s) | **3** (0.25 s) — extension |
| `frps` with `[auth] tokenSource` → a missing file | 1 (0.26 s) | **3** (0.25 s) — extension |
| `frpc` with `[store] path` → a file that is not JSON, named `authstore.json` | 1 | **4** — was **3** before the typed classification |
| `frpc` with `[store] path` → the same file content, named `plainstore.json` | 1 | **4** (unchanged) |
| `frps` with `[auth] method = "token"`, `token = ""` | **does not exit** (starts and runs) | **3** — hardening divergence, not a code divergence |
| `frps` with `[auth] method = "oidc"` and no issuer | **2** (panics) | **3** — frp-rs refuses where Go panics |
| `frps` / `frpc` with `[auth] method = "OIDC"` (also `"Oidc"`, `" oidc"`, `"oidc "`, `"tokenn"`, a Cyrillic-о lookalike) | 1 | **1** — matched 2026-09-28 with the streams separate: Go stdout **54 B**, stderr **0 B**, whole stdout `invalid auth method, optional values are [token oidc]\n`; frp-rs stdout is that same 53-byte message **plus its `<path>: ` loader prefix and a final `\n`, so the byte count is path-dependent** (100 B for the 45-character path measured here; a reviewer measured 129 B for a 73-character one), stderr **0 B** |
| `frps` / `frpc` with `[auth] method = ""` (or no `method` key) | starts (rc only changes when signalled) | starts — Go's `util.EmptyOr(c.Method, "token")`, `pkg/config/v1/server.go:136-139` / `client.go:206-209` |
| `frpc verify -c <method = "OIDC">` | 1 | **1** — `Config file <path> is invalid: <path>: invalid auth method, …` on stdout, stderr 0 B (was **0**, `is valid`, before the shared policy) |
| `frpc verify -c <method = "oidc">` with **no** `auth.oidc.clientID`/`tokenEndpointURL` | 1 — **both** missing fields, joined: `auth.oidc.clientID is required; auth.oidc.tokenEndpointURL is required` (**71 B** stdout, 0 B stderr) | **1** — only the first: `auth.oidc.clientID is required`. Recorded divergence: Go's `ValidateOIDCClientCredentialsConfig` accumulates **every** message and joins them with `"; "` (`pkg/config/v1/validation/oidc.go:25-57`, called from `validation/client.go:113-117`), while frp-rs's `validate_oidc_client_config` returns at the first |
| `frpc --config-dir <nonexistent\|empty\|bad>` | **0** | **2** (deliberate) |
| `frpc --config-dir <good>`, service cannot run | 0 (0.027 s) | **1** (0.03 s) — the client lane now carries the service failure out, like `frps`; was **0** with nothing served |
| `frps --config-dir <…>` | 1 — `unknown flag: --config-dir` | 2 (extension flag) |
| `frps --config-dir -x` / `--config-dir --strict-config=false` | 1 — `unknown flag: --config-dir` | 2 (extension flag; the dash-shaped token is the value, so the directory read runs — was rc 1 ``--config-dir` requires an argument `DIR`` before the shared `-c <dash-value>` pass, see § CLI inputs) |
| `frpc -c empty.toml` (defaults only, peer accepts and never answers) | 1 after 10.04 s | 1 after 30.07 s |
| the same, with the port genuinely refusing | 1 after 0.026 s | 1 after 0.023 s |
| `frps` on an occupied `bindPort`, `auth.token` set | 1 | 1 |

The good-directory row is deliberately qualified: a directory whose service
actually *runs* is long-running on both sides and has no natural exit code, so a
`0` obtained by signalling a live process must never be recorded here. The `0` in
the Go column is measured for the case where the service cannot run (the example
config points at a closed port: Go exits 0 in 0.027 s after `frpc service error
for config file [frpc.toml]`), and it is the only directory-mode `0` this table
asserts. The frp-rs column exits **1** for that shape, in 0.03 s, after
`ERROR frpc: frpc service error for config file [<path>]: transport error: dial to
127.0.0.1:1: Connection refused (os error 61)`; the `-c` twin exits **1** in
0.02 s with the same transport error, so the two lanes agree again — this is the
`frpc --config-dir` item, where the lane used to report success while nothing was
served. The same `--config-dir` shape pointed at a peer that accepts TCP and never
answers is slower and no longer a `0` on this side either: re-measured with the
directory's config dialling `127.0.0.1:7000` (macOS Control Center accepts and
stays silent) → **Go 0 at 10.02 s, frp-rs 1 at 30.03 s** (`transport error: TLS
connect: TLS handshake did not complete within 30s` on stdout, stderr 0 B). Those
are the same timeouts as the `empty.toml` row, not the ~0.03 s of the refused
case.

The `frpc -c empty.toml` rows exist because the durations are **peer-dependent,
not a bound**. The default empty config dials `127.0.0.1:7000`; on the host these
were measured on, macOS Control Center *accepts* that port and never speaks frp,
so the timeout is what is being measured (10.04 s / 30.07 s, Go then frp-rs).
With a port that genuinely refuses, the same shape returns in ~0.02 s on both
sides. That case is a *runtime* stop, not a config-parse failure — the exit code
is 1 on both sides, which is what the row is for.

Some things this table does not say, each measured:

- **Directory mode is a deliberate divergence, not an oversight.** Go's
  `frpc --config-dir` returns **0** for a directory that does not exist, is
  empty, *or holds a config that fails to parse* — the bad case prints only
  `frpc service error for config file […]` and exits 0. A config that was never
  loaded is not a success, so frp-rs keeps its pre-existing non-zero refusal
  (`EXIT_CONFIG`/2) on that path. Go `frps` has no `--config-dir` flag at all
  (`Error: unknown flag: --config-dir`, exit 1); frp-rs's is an extension, and
  its dash-valued form (`--config-dir -x`) takes the same 2 rather than the
  parser's old rc 1 refusal, because `--config-dir` is one of the four flags the
  shared `-c <dash-value>` pass covers (§ CLI inputs).
- **`EXIT_AUTH`/3 is an extension, and its documented example is
  `auth.tokenSource`.** Worst measured case: a `tokenSource` whose file does not
  exist exits **3** on both binaries, where Go exits **1** immediately
  (`failed to resolve auth.tokenSource: failed to read file …`). A rejected
  login is *not* an example: it leaves the client through `service.run()` and
  exits **1**, matching Go. The two server-side arms are pinned too: the empty
  token refusal (below) and `[auth] method = "oidc"` with no issuer.
- **`EXIT_BIND`/4 is not specifically a bind error** — it is the daemons' tag for
  *any* service-construction error that is not an auth one. Measured input:
  **`frpc`** with `[store] path` pointing at a file that is not JSON exits **4**,
  where Go exits **1** (`failed to create store source: … failed to parse
  JSON: …`). It is an frpc example on purpose: `[store]` is not a key Go's *frps*
  accepts (`json: unknown field "store"`), and on frp-rs frps the same key is also
  an unknown-field error, both rc 1. A real port conflict does *not* take this
  arm — `frps` on an occupied `bindPort` returns 1 on both sides, because the
  listener binds inside `service.run()`.
- **The code is chosen by `InitErrorKind`, never by the message text** (the
  change that closed `TODO.md:5290`). The constructor tags each failure where it
  is raised (`frp_core::init_error`), and every daemon arm reads only that tag.
  The old contract was `is_token_error` → `msg.contains("token") ||
  msg.contains("auth")` over the formatted error, which embeds the config path and
  any URL in the config; a callable classifier like it no longer exists in
  `frp-core`. The regression is pinned by the *flip control* in
  `frpc/tests/cli_exit_codes.rs`:
  `malformed_store_file_exits_4_regardless_of_the_file_name` runs the identical
  malformed-`[store]` failure under `authstore.json` and `plainstore.json` and
  requires **4** from both, so a reversion to a text match (which gives 3 for the
  first name, as the base commit did) fails the test. That failure was measured
  by re-introducing the substring expression in `frpc`'s arm: the test failed on
  the `authstore.json` iteration with `left: Some(3)`, `right: Some(4)`. The
  second control is
  `oidc_construction_failure_exits_3_whatever_the_issuer_path` (two auth-free
  issuer paths, both must be 3; measured `left: Some(4)` on a revert).
  **Coverage limit, stated because a partial guard must name what it does not
  cover:** both mutant-detecting pins are in the **client** file. No test
  distinguishes `frps`'s typed arm from a substring test — every reachable frps
  construction message contains `auth` or `token` (see the frps bullet below), so
  a substring mutant in `frps/src/main.rs` passes all 19 tests of
  `frps/tests/cli_exit_codes.rs`. Verified by attempting exactly that mutant. The
  frps arm's correctness therefore rests on the code plus the kind → code unit
  tests in `frp-core/src/init_error.rs`, not on a failing-on-mutant test; the
  `InitErrorKind` swap that *would* be caught by those unit tests is the only
  frps-reachable mis-tag there is, since 3 is the only code frps can produce.
- **Both construction codes are deliberate extensions, kept after weighing the
  collapse.** Grounds, and what would reverse it: the argument is in the
  *Decision* paragraph above. If Go ever grows a per-class exit scheme, or if a
  caller is found that must see exactly `1`, the collapse becomes the cheaper
  option — deleting the tag and returning `EXIT_RUNTIME` from the three daemon
  arms is the whole change, and the tests named here would move with it.
- **Two inputs where the two binaries disagree without a like-for-like exit
  code** — one where frp-rs refuses and Go does not, one where Go crashes on a
  code frp-rs handles:
  - `frps` with `[auth] method = "token"` and an empty `token`: frp-rs exits
    **3** in ~0.01 s (`security misconfiguration: CRITICAL: [auth].token …
    server would accept ALL connections`); Go **starts and keeps running**
    (`frps started successfully`, still alive after 8 s in the last measurement,
    then killed by the probe), because it has no such check. This is a hardening
    divergence, not the same failure with another code — do not describe it as
    "Go exits 1 here". Go exits 1 on that config only when the port is *held*,
    which is the occupied-`bindPort` row above. It is pinned on its own
    (`empty_token_refusal_is_a_hardening_divergence_go_does_not_have`) precisely
    because, being a *refusal*, it would survive a collapse of the codes as
    exit 1 and therefore must not be argued from the 3/4 decision.
  - `frps -c <[auth] method = "oidc"` with no issuer>`: frp-rs refuses with
    **3**; Go **panics** (`panic: Get "/.well-known/openid-configuration":
    unsupported protocol scheme ""`) and its runtime exits **2** — a code frp-rs
    uses only for a `--config-dir` refusal, never for a service-construction
    failure. Go does exit here, so this bullet is *not* a
    "refuses-where-Go-does-not" case. That panic is also why no blanket statement
    like "Go only ever returns 0 or 1" belongs in this document. Pinned by
    `oidc_without_an_issuer_is_refused_with_3_where_go_panics`.
  - **The pre-change 3-vs-4 flip is a *client* property, and it is measured.**
    `frps` was never the daemon where the coupling was reachable: every frps
    construction failure already carried `auth` or `token` in its message (an
    OIDC dial failure through the `Cannot start frps with OIDC auth: …` wrapper
    in `frp-server/src/service.rs`, the startup refusals through
    `check_startup`'s `[auth]` text), so at `d0f9ec5` **frps exited 3 for every
    reachable construction failure and `EXIT_BIND`/4 was unreachable there** —
    measured for `/authz`, `/zzz`, a missing `tokenSource`, an empty token, a
    missing OIDC CA file, an empty issuer and an empty audience, all 3 at base
    and all 3 at the head. `frpc`'s OIDC path is where the flip is real: with
    `[auth] method = "oidc"` and **no** `oidc.tokenEndpointURL`, `OidcClient::new`
    fetches `<issuer>/.well-known/openid-configuration`
    (`frp-core/src/auth.rs:1333-1348`) and the error embeds that URL, so at the
    base commit an issuer path containing `auth` gave **3** while four auth-free
    paths (`zzz`, `plain`, `nope`, `x`) gave **4** — each of the five repeated
    four times, one fresh config and one fresh closed port per run, rc read
    directly from the child. Every issuer path is **3** at the head. A missing
    `oidc.trustedCaFile` is the same family (`OIDC client: failed to read CA
    cert …`: base 4 at an auth-free path, head 3).
    **A confound worth recording**, because it produced two wrong probe
    readings before it was isolated: the claim is about the *message*, and the
    message does not contain the config path, so the config's own directory name
    must not vary between the arms being compared. An earlier version of this
    probe used `mktemp -d` per run, whose random suffix can itself spell
    `auth`; that made two nominally identical arms disagree. Isolated directly:
    with the issuer path `/zzz` held fixed, an auth-bearing and an auth-free
    config directory both give base **4** and head **3**, so the directory name is
    not what the classifier was reading — the URL is. With the directory name held
    fixed per arm the matrix above is deterministic (four runs per cell, same rc
    every time).
    This flip has no like-for-like Go row, **because Go's `frpc` has no
    `auth.oidc.issuer` key at all** — measured, `json: unknown field "issuer"`,
    rc 1 — not because the client starts. The `[store]` fixture below is the flip
    control that *has* a Go row (Go exits 1 on both names). Pinned by
    `frpc/tests/cli_exit_codes.rs::oidc_construction_failure_exits_3_whatever_the_issuer_path`,
    which also fails on a text-classifier revert (measured: `left: Some(4)`,
    `right: Some(3)` on the `zzz` arm).

  A third case — `frpc verify -c <config whose [[proxies]] block has an unknown
  key>` exiting **0** here against Go's **1** (`decode proxy at index 0: …
  unknown field "notAKnownProxyKey"`) — **was** in this list and is now a
  like-for-like **1**: `check_strict` walks the array elements
  (`TODO.md:2447`), so frp-rs prints `unknown field
  "proxies[0].notAKnownProxyKey"` and exits 1 exactly where Go does.

Tests that pin this — real binaries, no mocks:
`frpc/tests/cli_exit_codes.rs` (`frpc -c <bad>` start, `verify -c <bad>`,
`verify -c <missing>`, a `verify -c <good>` positive control, the directory-mode
divergence for a missing / empty / invalid directory, the `tokenSource` → 3 case,
the **flip control** `malformed_store_file_exits_4_regardless_of_the_file_name`
— one failure class under two file names, both 4 — and the client-side OIDC pin
`oidc_construction_failure_exits_3_whatever_the_issuer_path`, which is the *other*
half of the same control: it runs two auth-free issuer paths and requires 3 from
both, and it is `#[cfg(feature = "full")]` because the `oidc` feature is not in
`tiny`; under `--features tiny` the same two assertions run against `frpc-tiny`)
and `frps/tests/cli_exit_codes.rs`
(`frps -c <bad>`, `-c <missing>`, a starts-then-SIGTERM positive control, the
extension flag's refusal, and the three construction-code pins
`unresolvable_token_source_exits_3_where_go_exits_1`,
`empty_token_refusal_is_a_hardening_divergence_go_does_not_have`,
`oidc_without_an_issuer_is_refused_with_3_where_go_panics`). The kind → code
mapping itself is asserted in `frp-core/src/init_error.rs`. **Where the guard is
weak, stated rather than implied:** the frps arm's typed classification is *not*
test-backed — every reachable frps construction message contains `auth`/`token`
(see above), so a substring mutant in `frps/src/main.rs` passes all 19 of that
file's tests. The guarantee on that daemon rests on the code and on the kind →
code unit tests, not on a failing-on-mutant integration test; the mutant-detecting
pins are the two client ones. The admin-subcommand
refusals stay pinned by `frpc/tests/admin_cli.rs`, and the repeated-`-c` /
empty-`addr` inputs by `frpc/tests/cli_inputs.rs`. Executing lanes: `Run frpc CLI
tests`, `Run frps CLI tests` and `Run frpc's CLI exit-code tests under tiny` in `.github/workflows/ci.yml`
(the `frps` lane and the `tiny` lane were added with these tests — nothing ran a
`cargo test` target of the `frps` package, or executed the `tiny` CLI binary,
before them). The `frps` lane's count literal moved 16 → 19 with the three
server-side pins; the `tiny` lane's stayed 11, because the client's flip control
replaced the single-name store test rather than adding one.

#### Output stream and shape on a config-load failure

**Matched (2026-09-27): the stream, and the shape of each line.** Every
single-config failure on this surface is now written as **bare** line(s) on
**stdout** with nothing on stderr — like Go's `fmt.Println(err); os.Exit(1)`, with
no ANSI, no timestamp/level/target prefix and no duplicated `error=` field. It is
**one line per rejected key**: with one offending key Go and frp-rs each print one
line, and with N ≥ 2 frp-rs prints N where Go prints only the first — that half is
a recorded divergence, not a match (see the end of this subsection). Measured
against Go v0.71.0 (darwin/arm64) with the two streams redirected to separate files
and the exit status read directly (never through a pipe); Go then frp-rs:

| command | Go stdout | Go stderr | frp-rs stdout | frp-rs stderr |
|---|---|---|---|---|
| `frpc -c <unknown-key config>` | 38 B (37 B of text + `\n`), `json: unknown field "notAKnownFrpKey"` | 0 B | one bare line per rejected key, `unknown field "notAKnownFrpKey" in config file <path>` | 0 B |
| `frpc verify -c <unknown-key config>` | 38 B, same text | 0 B | one bare line per rejected key, `Config file <path> is invalid: unknown field … in config file <path>` | 0 B |
| `frpc verify -c <missing>` | `open <path>: no such file or directory` | 0 B | one bare line, `Config file <path> is invalid: <path>: failed to read config file: …` | 0 B |
| `frps -c <unknown-key config>` | 38 B, same text | 0 B | one bare line per rejected key, `unknown field "notAKnownFrpKey" in config file <path>` | 0 B |

The frp-rs byte counts are deliberately not given: the line embeds the config
path, so the total moves with it — the same one-key content measured **75 B** on
the scratch path this table was first written with and **70 B** on
`/tmp/f1-probe/cb1.toml`, against Go's path-independent 38 B. The *line count* and
the per-line shape are the claims here, not the byte total.

Anchors in the Go tree: `cmd/frpc/sub/root.go:80` (the `RunE`'s
`fmt.Println(err); os.Exit(1)` on the `runClient` error), `cmd/frpc/sub/verify.go:59`
(the same pair in `verifyCmd`), `cmd/frps/root.go:70` (the `cfgFile != ""` load arm).
Before, the daemon start path wrapped the error in an ANSI-coloured `tracing`
record on stdout — timestamp, level, target, and the message repeated in a
trailing `error=` field — and `frpc verify` put its refusal on stderr. Both
`init_logging(&args, None)` / `init_logging(&cli, None)` calls are gone from the
arm that exits before any log record: Go installs its logger only after a
successful load (`startServiceWithAggregator`). `frp-core`'s `EXIT_CONFIG`/2
directory refusals and the per-file `Failed to load config from [...]` lines of
the `--config-dir` extension keep the logging shape — that mode has no Go
counterpart on `frps` at all and exits 0 on Go for `frpc`, so there is no Go line
to match.

**Still divergent, deliberately: the wording.** frp-rs names the config file
(`unknown field "x" in config file <path>`, plus a `did you mean 'y'?` suggestion
within edit distance 3); Go prints the codec's `json: unknown field "x"` with no
path. Matching Go byte-for-byte would mean adding a literal `json: ` prefix to a
message frp-rs also emits for TOML/YAML/INI files and dropping the path that is
the only file identity in `--config-dir` mode and in the admin `reload`/`status`
refusals (which already print this same bare stdout line). So the stream and the
shape are Go's and the sentence is not. `frpc verify`'s **success** line was a
second, adjacent divergence (Go prints exactly `frpc: the configuration file
<path> syntax is ok`, frp-rs printed `Config file <path> is valid`); it is
**closed** — `frpc verify` now prints Go's sentence as its first line. What
remains is that frp-rs then prints three indented summary lines Go does not
(`  Server:`, `  Proxies:`, `  Visitors:`), kept because
`frpc/tests/legacy_ini_fixture.rs` observes the vendored legacy fixture's 43
proxies / 2 visitors through them; measured on a minimal config, Go stdout 52 B
and frp-rs 104 B, the 52 B delta being exactly those lines. The `frps verify` /
`frpc verify` asymmetry is therefore narrowed to those three lines, not the
sentence. Rows elsewhere in this document measured before that change still
quote the old `Config file … is valid`; their rc, stream and verdicts are
unaffected.

**Still divergent, deliberately: the line count at N ≥ 2.** `run_strict_check`
(`frp-core/src/config/strict.rs`) collects **every** unknown key and returns
`errors.join("\n")`, so the single `println!("{e}")` emits one line per rejected
key; Go sets `DisallowUnknownFields` on one `decoder.Decode(out)` call
(`pkg/util/jsonx/json_v1.go:43-44`, reached from `pkg/config/v1/decode.go:29-33`)
and returns at the **first** one, so its whole output is that one line. Measured
with three unknown keys in one config, streams separated and the exit status read
directly:

| command | Go stdout | frp-rs stdout |
|---|---|---|
| `frpc -c <3 unknown keys>` | rc 1, 36 B, **1 line**, `json: unknown field "anotherBadKey"` | rc 1, **3 lines** (one per key), stderr 0 B |
| `frpc verify -c <3 unknown keys>` | rc 1, 36 B, **1 line**, same text | rc 1, **3 lines** — the first prefixed `Config file <path> is invalid: `, stderr 0 B |
| `frps -c <3 unknown keys>` | rc 1, 36 B, **1 line**, same text | rc 1, **3 lines** (one per key), stderr 0 B |

The key named first is the same on both sides, and it is chosen by **key name,
not document position**: with the document order permuted to
`zzzBadKey, anotherBadKey, thirdBadKey` Go still names `anotherBadKey` (and with
`zzzBadKey, aaaBadKey` it names `aaaBadKey`), while frp-rs names `anotherBadKey`
and then `thirdBadKey`, `zzzBadKey` — sorted the same way. So the divergence is
purely the *count*: all keys versus the first. Reporting all of them is kept
deliberately — listing every rejected key is what strict mode is for, and matching
Go would mean discarding N−1 of them; a caller that wants Go's single line reads
the first line. This count is pinned at the collector, not the CLI:
`strict_check_reports_every_unknown_key_not_just_the_first` in
`frp-core/src/config/tests.rs` (every CLI fixture in the two `cli_exit_codes.rs`
files is a one-unknown-key config, so none of them can see the count move).

The third row of the item — `--strict-config=foo` — needs no change here: both
binaries already write that refusal to **stderr** and exit 1, and the text
difference (Go's pflag `invalid argument "foo" for "--strict-config" flag:
strconv.ParseBool: …` followed by the full cobra usage block; frp-rs's
`` `foo` is not expected in this context `` with no usage) is recorded in
[§ `--strict-config`](#--strict-config-the-space-separated-value-form) and in
the `TODO.md` item of that name.

These tests pin the shape, not just the code: the two `-c <bad>` /
`verify -c <bad>` tests assert the **exact** stdout bytes and an empty stderr,
and the `<missing>` pair asserts the **start** of the stdout line (a prefix pin,
not a whole-line one) — `<path>: failed to read config file:` for `frps`,
`Config file <path> is invalid: <path>:` for `frpc verify` — so a reintroduced
timestamp/level prefix or ANSI escape fails. The tiny module asserts the same for
`frpc-tiny`. All are in the two `cli_exit_codes.rs` files named above, on the same
three lanes. Nothing was added to or deleted from **those two files** by that
round, so the guarded counts `env.FRPS_CLI_TESTS` (then `16` =
`frps/tests/cli_exit_codes.rs`) and `env.FRPC_TINY_CLI_TESTS` (`11` = the tiny
run of `frpc/tests/cli_exit_codes.rs`) were unchanged by it, and neither literal
counts the N ≥ 2 pin above, which is a unit test in `frp-core`. **The `frps`
literal has moved twice since** — to `19` with the typed exit-code pins (#393)
and to **`26`** with `frps verify` (the `FRPS_CLI_TESTS` value in
`.github/workflows/ci.yml` is the single home; do not read a count from this
paragraph).

#### CLI inputs: repeated `-c`, an empty `webServer.addr`, case-insensitive keys

Three `frpc` inputs Go accepts and frp-rs used to refuse (`TODO.md:3672`). Two
are now Go-faithful; the third is a **recorded divergence**, because the honest
fix is not bounded and a partial one would be a false claim of parity. Measured
2026-09-26 against Go frp **v0.71.0** (darwin/arm64) and the frp-rs `frpc` at
this branch's head.

**1. A repeated `-c`/`--config` is last-wins — now matched.** Go registers `-c`
with pflag `StringVarP` in a package-level initializer (`cmd/frpc/sub/root.go`),
so each occurrence overwrites the last and repetition is never an error. frp-rs's
bpaf parser exited before loading anything with
``argument `-c` cannot be used multiple times in this context``. Every frpc
config argument now goes through `config_arg()` (`frp-core/src/cli.rs`), which is
`.last()` — bpaf's contradicting-options combinator — wrapped in the same
`fallback`/`optional` each command already had. Measured, both binaries:

| command | Go v0.71.0 | frp-rs (now) | frp-rs (before) |
|---|---|---|---|
| `frpc status -c noweb.toml -c p7499.toml` | dials `127.0.0.1:7499` | dials `127.0.0.1:7499` | rc 1, ``argument `-c` cannot be used multiple times`` |
| `frpc reload \| stop -c noweb.toml -c p7499.toml` | dials `7499` | dials `7499` | same refusal |
| `frpc status -c p7499.toml -c noweb.toml` | `web server port should be set …` | same sentence | same refusal |
| `frpc verify -c noweb.toml -c p7499.toml` | `syntax is ok` for `p7499.toml` | `Config file …/p7499.toml is valid` | same refusal |
| `frpc status --config p7499.toml -c p7498.toml` | dials `7498` | dials `7498` | same refusal |
| `frpc status -cp7498.toml` / `-c=p7498.toml` | dials `7498` | dials `7498` | dials `7498` (bpaf already accepted both) |
| `frpc status -c p7498.toml -c` (dangling) | `Error: flag needs an argument: 'c' in -c` | ``Error: `-c` requires an argument `FILE` `` | same refusal |
| `frpc status -c ""` | rc 1, `open : no such file or directory` | rc 1, `: failed to read config file: …` | same (message shape differs; see the output-shape note above) |

The last two rows are the guard rails: an empty value stays a value (no fallback
to the `127.0.0.1:7400` default) and a dangling occurrence is still an error, not
a reused previous value. Pinned by `frpc/tests/cli_inputs.rs` and the
parser-level tests in `frp-core/src/cli.rs`. `frps` is unchanged — a separate
surface, not part of that item.

Three argv shapes around that change were **still divergent** at the head of
`fix/frpc-cli-inputs`, all measured on the same pair of configs. Two of them
were the "which persistent root flags each subparser declares" question and are
**matched now** — see [§ The persistent rootCmd flags on every
subcommand](#the-persistent-rootcmd-flags-on-every-subcommand) below. The third
is a different rule and remains divergent:

Every Go cell below ends rc 1 **because nothing is listening** on the port the
command resolves to (the connection refusal); with a mock answering, the same
argv exits 0. What the cells pin is *which port* Go resolved, so a reader running
a listener should expect 0, not a contradiction:

| argv | Go v0.71.0 (no listener) | frp-rs (before) | frp-rs (now) |
|---|---|---|---|
| `frpc status -c --strict-config=false -c p7498.toml` | rc 1, dials `7498` — Go consumes `--strict-config=false` **as `-c`'s value** (measured: `frpc status -c --strict-config=false` alone is `open --strict-config=false: no such file or directory`, and had it been parsed as the flag the first `-c` would have dangled), then the later `-c p7498.toml` overwrites it | rc 1, ``-c` requires an argument `FILE`` | rc 1, dials `7498` |
| `frpc status -c p7498.toml --config-dir cDir` | rc 1, dials `7498` (`--config-dir` exists on the root command) | rc 1, `` `--config-dir` is not expected in this context`` | rc 1, dials `7498` |
| `frpc status -c p7498.toml -- -c p7499.toml` | rc 1, dials `7498` (flags after `--` are positional) | rc 1, `` `-c` is not expected in this context`` | **rc 1, `` `-c` is not expected in this context`` — still divergent** |

The third row is not a persistent-flag shape at all: Go's rule there is "ignore
positional arguments", which applies to every `frpc` subcommand and to plain
words as well — measured, `frpc status extra` loads `./frpc.ini` (rc 1, no
`[webServer]`-style error) and `frpc tcp … extra` starts the proxy, while frp-rs
refuses a leftover token with or without `--`. It is recorded here rather than
half-fixed, because "accept positionals" cannot be narrowed to the `--` form
without also swallowing unknown flags: Go itself refuses `frpc tcp -c -- -foo`
with `unknown shorthand flag: 'f' in -foo` (rc 1), so the rule is "ignore
positionals, still reject unknown flags", which is not a bpaf positional parser
away. It is filed with the single-proxy item in `TODO.md:4506`.

**2. An empty `webServer.addr` is completed to `127.0.0.1` — on frpc and frps
alike, and only the empty string.** Go's `ClientCommonConfig.Complete()` calls
`c.WebServer.Complete()` (`pkg/config/v1/client.go:96`), which is
`c.Addr = util.EmptyOr(c.Addr, "127.0.0.1")` (`pkg/config/v1/common.go:71-72`).
frp-rs's serde field default only fires when the key is **absent**, so an explicit
`addr = ""` survived and every dial became a lookup of the empty host. Measured
with `[webServer] port = 7499` and the `addr` varied:

| `addr` | Go v0.71.0 | frp-rs (now) | frp-rs (before) |
|---|---|---|---|
| `""` | dials `127.0.0.1:7499` | dials `127.0.0.1:7499` | `connect :7499: failed to lookup address information` |
| `" "` | rc 1, `parse "http:// :7499/api/status": invalid character " " in host name` | rc 1, the whitespace host reaches the dialer | same |
| `"0.0.0.0"` | dials `0.0.0.0:7499` | literal | literal |
| `"::1"` | dials `[::1]:7499` | literal | literal |
| `"localhost"` | dials `[::1]:7499` (dialer resolution) | dialer resolution | dialer resolution |

The rule mirrored is exactly Go's: **the empty string becomes `127.0.0.1`;
anything else is used verbatim** — no trimming, no whitespace special case. The
completion lives in `ClientConfig::complete_with_heartbeat_set`
(`frp-core/src/config/client.rs`), the same load/complete boundary the item
names, so it applies to the admin subcommands *and* to the client's own
`[webServer]` admin listener. Pinned by `frpc/tests/cli_inputs.rs` (empty,
whitespace and no-`[webServer]` shapes) plus `frp-core/src/config/tests.rs`.

**The server side is matched too — this paragraph used to say it was not, and
the earlier draft it corrected had claimed parity before the code had it.** Go's
`ServerConfig.Complete()` calls `c.WebServer.Complete()`
(`pkg/config/v1/server.go:107`) — the same `EmptyOr(Addr, "127.0.0.1")` as the
client — *before* the `if c.WebServer.Port > 0 { c.WebServer.Addr =
util.EmptyOr(c.WebServer.Addr, "0.0.0.0") }` branch at `:116-117`, so that
branch is dead and an explicit `addr` that is empty with a set port stays
loopback. `frp-core/src/config/server.rs` used to default the address to
`0.0.0.0` when the port was set — the second half of the two-step without the
first, i.e. the dashboard on **every** interface where Go keeps it on the
loopback — and now fills the empty string with `127.0.0.1` first, with no
wildcard branch at all. Measured on Go v0.71.0 and frp-rs (`--features
dashboard`), same config file for both (`[webServer] addr = ""` or the key
present/absent as tabled, one free dashboard port and one free `bindPort` per
row, `user`/`password`, plus an `[auth]` token so neither binary refuses to
start), address read back with `lsof -nP -iTCP:<port> -sTCP:LISTEN`:

| `addr` | dashboard port | Go v0.71.0 | frp-rs before | frp-rs now |
|---|---|---|---|---|
| `""` | 17701 | `dashboard listen on 127.0.0.1:17701`; `TCP 127.0.0.1:17701 (LISTEN)` | `Dashboard listening on 0.0.0.0:17701`; `TCP *:17701 (LISTEN)` | `127.0.0.1:17701` |
| absent | 17703 | `127.0.0.1:17703` | `127.0.0.1:17703` (serde default) | `127.0.0.1:17703` (unchanged) |
| `"0.0.0.0"` | 17705 | `0.0.0.0:17705`; `TCP *:17705 (LISTEN)` | same | same |
| `"::1"` | 17707 | `[::1]:17707` | same | same |

The completion fills only the empty string — an absent key is already
`127.0.0.1` through the serde default, and every explicit non-empty address
(including the wildcard and `"::1"`) is used verbatim, which is what the
positive control in the spawn test checks. Pinned on the **bound address** by
`dashboard_explicit_empty_addr_binds_loopback_only` and
`dashboard_absent_addr_binds_loopback_only` in
`frp-server/tests/dashboard_integration.rs` (both spawn the real `frps` binary
from this lane's `FRPS_BIN`; the wildcard case is their positive control,
because a host whose non-loopback probe could never connect must fail rather
than let the two loopback assertions pass vacuously), and on the completed
value by `server_web_server_addr_empty_is_completed_to_localhost` in
`frp-core/src/config/tests.rs`.

**2b. `frps` CLI overrides are applied *before* `ServerConfig::complete()`, as
Go applies its flags before `ServerConfig.Complete()`.** `frps` reads
`./frps.toml` (or `-c <file>`) and overlays the CLI flags only when no
`-c`/`--config-dir` is given (Go parity, § CLI exit codes), so the values that
reach the listener are the merged ones. Until this change the file was completed
first (`frp-core/src/config/file.rs`) and the overrides were written afterwards
(`FrpsArgs::override_server_config`), which made every **empty** override bypass
the completion that fills it. Go's ordering is *per lane*: only the flags-only
path completes a struct the flags have populated (`cmd/frps/root.go:77-83`); the
`-c` path loads a fresh struct from the file and completes that
(`pkg/config/load.go:313`, `:318-321`), discarding the pflag-bound one, which is
why Go ignores the flags there — and why frp-rs, which also ignores them on `-c`
(`FrpsArgs::cli_overrides_enabled`), matches Go on that lane for a different
reason. frp-rs's override lane has the same **order** as Go's flags-only path (overlay,
then complete) — but the **values** are not thereby the same: Go pre-seeds every
pflag default into the struct before `Complete()` runs (`pkg/config/flags.go:230-255`,
so e.g. `bind_addr` is already `0.0.0.0` and `proxy_bind_addr` already `0.0.0.0`),
while frp-rs's override lane keeps whatever the file deserialized to and only
overwrites the flags the operator actually passed. The loader now has an un-completed entry
point (`load_server_config_uncompleted`) that `frps/src/main.rs` overlays and
completes, and `ServerConfig::complete` gained Go's
`c.BindAddr = util.EmptyOr(c.BindAddr, "0.0.0.0")`
(`pkg/config/v1/server.go:110`, before the `ProxyBindAddr` inheritance at
`:112-114` and the `BindPort` fill at `:111`).

Since #427 the three zero-valued log flags (`--log-level ""`, `--log-file ""`,
`--log-max-days 0`) are skipped entirely by the override lane rather than written
through and completed, so a file's `[log]` values survive a deliberately empty flag;
`--log-format` still writes through on that lane because it is an frp-rs-only flag
with no Go completion to mirror (`TODO.md` residue R2 records the remaining adjacent
divergence — R1, the `-c`-only lane's non-empty log flag, is closed by the mask at
`frps/src/main.rs:439`, which withholds all four log flags there).

Measured against Go frp **v0.71.0** (darwin/arm64) and frp-rs (base `80199f4`),
cwd holding a `frps.toml`, one free control port and one free dashboard port per
row, `[auth] token` set and `[webServer] user`/`password` set, address read back
with `lsof -nP -iTCP:<port> -sTCP:LISTEN`:

| argv (config file present) | Go v0.71.0 | frp-rs before | frp-rs now |
|---|---|---|---|
| `--dashboard-addr ""` (`[webServer] port` set, credentials) | `dashboard listen on 127.0.0.1:19802`; `TCP 127.0.0.1:19802 (LISTEN)` | `Dashboard web UI starting on :19802` + `failed to lookup address information`; **nothing** on 19802, control listener alive | `127.0.0.1:19802`; `TCP 127.0.0.1:19802 (LISTEN)` |
| the same flag, **no** credentials | *(masked by the no-auth force-bind: frp-rs already bound `127.0.0.1`)* | `binding to 127.0.0.1:19804 (localhost only)` | unchanged |
| `--bind-addr ""` (`[auth] token`, `bindPort` in the file) | `frps tcp listen on 0.0.0.0:19805`; `TCP *:19805 (LISTEN)` | `frps starting on :19805` + `failed to lookup address information`, exit 1, nothing bound | `0.0.0.0:19805`; `TCP *:19805 (LISTEN)` |
| `--bind-port 0` | `create server listener error, listen tcp 0.0.0.0:7000: bind: address already in use` (tries the default 7000) | `frps starting on 127.0.0.1:0`, binds an ephemeral port | `frps starting on 127.0.0.1:7000` |
| `bindAddr = ""` **in the file** (no flag) | `0.0.0.0:19815` | exit 1, nothing bound | `0.0.0.0:19815` |
| `--config-dir <dir>` with `bindAddr = ""` in the file (the lane that never overlays flags — it still resolves through the completing `load_server_config`) | *(no `frps --config-dir` on Go: `Error: unknown flag: --config-dir`, rc 1; the `-c` analogue binds `0.0.0.0`)* | **rc 0 with nothing bound** — and *not* silent: it logs `ERROR frps: frps service error for config file […]: failed to lookup address information`. The **underlying error text** is the same one `-c` reports, but the message and the disposition differ: `-c` prints `ERROR frps: frps error: failed to lookup address information` and **exits 1**, while this lane wraps it per config file and **exits 0** — the defect is that exit code. **Superseded**: the `bind_addr = ""` fill now covers this lane too (measured at `971e0fa0`: `frps --config-dir` with that file logs `listener started on 0.0.0.0:19961` and keeps running; `SIGTERM` rc 0 once the shutdown handler is installed (`frp-server/src/service.rs:965` — a signal landing in the startup window dies with the default disposition, rc 143, on **both** lanes), so the row keeps the round's measurement and no longer describes today's behaviour | `0.0.0.0:19881` listening |
| the no-auth force-bind, no flag (control case) | n/a | `127.0.0.1` | unchanged |

Pinned by `frps/tests/cli_completion.rs` (`--dashboard-addr ""` with
credentials → dashboard reports and dials `127.0.0.1:<port>` and no
`failed to lookup address information`; `--bind-addr ""` → listener reports
`0.0.0.0:<port>`; `--bind-port 0` → the completed default 7000; plus an
**absent-flag control** per shape asserting the configured `bind_addr` /
`[webServer].addr` is what binds), executed by the
`Run frps CLI completion tests (merged-config completion order)` step in
`.github/workflows/ci.yml` (a different target from the guarded
`cli_exit_codes`, so the `env.FRPS_CLI_TESTS` literal does not move with it — it
reads `26` at the `frps verify` head; it passes
`--features dashboard`, without which the dashboard regression is not covered —
against a true pre-fix no-dashboard binary that configuration is 3 passed /
3 failed (of six), with the dashboard shape **passing** because there is no
dashboard listener to hand an empty address to; against a pre-fix dashboard
binary it is 2 passed / 4 failed, dashboard shape included).
The completion itself is pinned by
`server_bind_addr_empty_is_completed_to_wildcard` and
`server_completion_must_run_on_the_merged_cli_config` in
`frp-core/src/config/tests.rs`.

Three things this does **not** claim:

- **frp-rs still needs `./frps.toml`; Go's flags-only mode has no file at all.**
  In a directory without one frp-rs exits with the load refusal on stdout
  (`frps.toml: failed to read config file: No such file or directory (os error
  2)`, 78 B, stderr empty, rc 1 — the `Failed to load config: ` prefix this line
  used to carry was removed by the output-shape round in § CLI exit codes).
  Where a file
  *is* present, the CLI-override lane above is the frp-rs analogue of Go's
  flags-only lane and is what was measured — the same **order** (overlay, then
  complete), not the same **values**, for the reason given at the top of this
  section (Go pre-seeds every pflag default; frp-rs keeps the file's values except
  where a flag overrides). Go's flags-only `--dashboard-addr ""`
  also completes to `127.0.0.1` (`WebServer.Complete()`), but Go's flags-only
  **absent** `--dashboard-addr` binds `0.0.0.0`, where frp-rs keeps the file's
  `127.0.0.1`. Measured and explained: Go registers the flag with its default
  written straight into the struct field —
  `StringVarP(&c.WebServer.Addr, "dashboard_addr", "", "0.0.0.0", …)`
  (`pkg/config/flags.go:238`) — so an absent flag supplies `0.0.0.0` and the
  `util.EmptyOr` in `WebServer.Complete()` cannot fire; the later
  `if Port > 0 { Addr = EmptyOr(Addr, "0.0.0.0") }` branch cannot fire either
  (`Addr` is already `0.0.0.0`), so the binding comes from the pflag default
  itself, not from that branch. An
  explicit empty flag overwrites the field with `""` and is then completed to
  `127.0.0.1`. That flags-only shape has no frp-rs equivalent to match (frp-rs
  always reads a file in this lane), so nothing changed there; the row is
  recorded, not mirrored.
- **`proxy_bind_addr` now inherits the *post-override* `bind_addr` — a real,
  measured behaviour change in the `--bind-addr` lane.** Go's `ProxyBindAddr`
  inherits `BindAddr` when empty (`server.go:112-114`) *inside* `Complete()`, so
  it inherits the value the flags put there. frp-rs now does the same; before,
  the inheritance had already happened against the file's value, so the proxy
  listener ignored `--bind-addr`. Measured with a real `frpc` registration and
  `lsof -nP -iTCP:<port> -sTCP:LISTEN -a -p <pid>` (file has no `proxyBindAddr`
  key; every row's control listener followed the flag in both binaries):

  | file `bind_addr` | argv | Go v0.71.0 proxy | frp-rs before | frp-rs now |
  |---|---|---|---|---|
  | `127.0.0.1` | *(none)* | `127.0.0.1:19872` (`-c`) | `127.0.0.1` | `127.0.0.1` |
  | `127.0.0.1` | `--bind-addr 0.0.0.0` | **flags-only equivalent** `--bind_addr 0.0.0.0 --proxy_bind_addr ""` → `*:19902`; the exact file+flag shape has no Go analogue, because Go's `-c` lane ignores the flags | `127.0.0.1` | `0.0.0.0` |
  | `0.0.0.0` | `--bind-addr 127.0.0.1` | **flags-only equivalent** `--bind_addr 127.0.0.1 --proxy_bind_addr ""` → `127.0.0.1:19904`; `-c` with the same file and flag stays `*:19874` (flags ignored) | `0.0.0.0` | `127.0.0.1` |

  The two Go rows are the measurement that decides whether the widening below is
  Go-correct, and they say it is — **but only with `--proxy_bind_addr ""` passed
  explicitly**, which is why it is spelled out in both rows. Measured on Go
  flags-only: `--bind_addr 127.0.0.1` **alone** puts the proxy listener on `*`,
  because pflag has already written `proxy_bind_addr`'s default `0.0.0.0` into the
  struct (`pkg/config/flags.go:234`) and `Complete()`'s
  `if c.ProxyBindAddr == ""` therefore never fires; adding
  `--proxy_bind_addr ""` is what lets the inheritance run and produce
  `127.0.0.1:19904`. With that flag present, an empty `proxyBindAddr` inherits the
  **post-flag** `bind_addr` (`Complete()` runs after pflag wrote the struct), so
  `--bind_addr 0.0.0.0 --proxy_bind_addr ""` → `0.0.0.0` and
  `--bind_addr 127.0.0.1 --proxy_bind_addr ""` → `127.0.0.1` — exactly what the
  head column does.
  The one thing frp-rs does that no Go lane does is combine a **file** value with
  an overriding flag: on Go those two never meet (the `-c` lane drops the flags,
  the flags-only lane has no file), so "file `bind_addr` plus `--bind-addr`" is an
  frp-rs-only shape, and the defensible half of the claim is that *within that
  shape* the completion follows Go's rule.

  So the proxy plane now **follows `--bind-addr` in both directions**. The
  widening row is the one to know about: a file that pins proxies to loopback
  while the operator passes `--bind-addr 0.0.0.0` had loopback-only proxy ports
  and now exposes them on the interface the control listener already uses — and
  symmetrically, a narrowing flag now narrows them. It is a consequence of doing
  what Go does (one `Complete()` on the merged struct) and it removes the split
  where the control listener moved but the proxies did not; per-proxy pinning is
  still available through an explicit `proxyBindAddr`, which the completion never
  touches. An earlier probe that used `--bind-addr` equal to the file value could
  not see this and wrongly recorded the change as unobservable.

**3. Config keys are matched case-sensitively — a recorded divergence, not
parity.** Go decodes with `encoding/json`, whose matching is case-insensitive
for **field and table names at every level**, including inside array items. That
is a property of the decoder, not of one struct, so it cannot be closed with a
bounded set of `#[serde(alias)]`: serde's aliases are exact strings, and a
complete fix means either per-field aliases for every case permutation across
the whole config tree or a canonicalising pre-pass in front of
`serde_json::from_value`. What *did* change is which way the array arm diverges:
`check_strict` now walks the `[[proxies]]`/`[[visitors]]`/`[[httpPlugins]]`
elements, so a mis-cased array key is **refused** in strict mode instead of being
dropped with exit 0 (the `cap-proxy.toml` row below). The value-level divergence
under `--strict-config=false`, and in the positions the walk does not reach,
is unchanged.

Measured against Go v0.71.0, cell by cell, with the exact configs named. `verify`
and `status` differ on the same file — `verify` parses and reports, while
`status` also has to resolve an admin address, which is where a dropped
`[webServer] port` turns into Go's refusal sentence:

| config | command | Go v0.71.0 | frp-rs strict | frp-rs `--strict-config=false` |
|---|---|---|---|---|
| `cap-top.toml` = `ServerAddr`/`ServerPort` | `verify -c …` | rc 0, `syntax is ok` | rc 1, `unknown field "ServerAddr" … did you mean 'serverAddr'?` | rc 0, `is valid` |
| the same | `status -c …` | rc 1, `web server port should be set …` | rc 1, the unknown-field error | rc 1, the same Go sentence |
| `caps-all.toml` = `SERVERADDR`/`SERVERPORT` | `verify -c …` | rc 0 | rc 1, `unknown field "SERVERADDR"` (no suggestion — distance > 3) | rc 0 |
| `caps-web.toml` = `ServerAddr`/`ServerPort` + `[webServer] port = 7499` | `status -c …` | rc 1, dials `127.0.0.1:7499` | rc 1, the unknown-field error | **rc 1, dials `127.0.0.1:7499`** |
| `port-only.toml` = `[webServer] Port = 7499` | `status -c …` | rc 1, dials `7499` | rc 1, `unknown field "web_server.Port" … did you mean 'port'?` | rc 1, `web server port should be set …` |
| `section-only.toml` = `[WebServer] port = 7499` | `status -c …` | rc 1, dials `7499` | rc 1, `unknown field "WebServer" … did you mean 'webServer'?` | rc 1, `web server port should be set …` |
| `cap-proxy.toml` = `[[proxies]] name/type` + `LocalPort`/`RemotePort` | `verify -c …` | rc 0 — accepted (Go's decoder matches object keys case-insensitively) | **rc 1 — refused by the array recursion (see below)** | rc 0 — dropped, `remote_port: 0` |

The last row is the sharp edge and the reason the earlier "refused (strict) or
silently mis-defaulted (lenient)" phrasing was wrong in **both** directions.
That row has since **changed** with the strict-mode array recursion
(`TODO.md:2447`): `cap-proxy.toml` is now refused in strict mode
(`unknown field "proxies[0].LocalPort" …`, exit 1, alongside
`proxies[0].RemotePort`), because `check_strict` walks the
`[[proxies]]`/`[[visitors]]`/`[[httpPlugins]]` elements with one exact-match key
set per **struct** (`PROXY_KNOWN_KEYS` and friends in
`frp-core/src/config/strict.rs:270`). Non-strict mode still drops the keys
(rc 0, `remote_port: 0`, `local_port: 80`).

- **Strict mode does not refuse everywhere: it walks only the tables it has a
  key list for.** `section_known_keys`
  (`frp-core/src/config/strict.rs:496`) has nine arms, plus the top level
  `check_strict` is entered with and, since the array recursion, the proxy /
  visitor / client-plugin / visitor-plugin / http-plugin element sets. Each
  walked position is listed here with a capitalised key measured as refused at
  the head: the top level (`"ServerAddr"`), then the nine arms — `[auth]`
  (`"auth.Token"`), `[log]` (`"log.Level"`), `[webServer]`
  (`"web_server.Port"`), `[transport]` (`"TcpMux"`), `[quic]`
  (`"quic.MaxIdleTimeout"`), `[observability]` (`"observability.OtlpEndpoint"`),
  `[store]` (`"store.Path"`), `[virtual_net]` (`"virtual_net.Address"`) and the
  server-only `[sshTunnelGateway]` (`"ssh_tunnel_gateway.BindPort"`; the client
  side has no such table) — and now a `[[proxies]]` element
  (`"proxies[0].LocalPort"`). Two categories still fall outside the walked set
  and are **dropped silently even in strict mode**, with `frpc verify` exiting 0:
  - **a table alias the normalizer leaves alone** — `check_strict` looks up the
    section by the spelling it sees, so a camelCase alias survives (no key list)
    and is not descended into. Measured with `[virtualNet] Address =
    "10.1.0.0/24"` (no array anywhere): Go `verify -c` fails with
    `VirtualNet feature is not enabled; enable it by setting the appropriate
    feature gate flag`, while frp-rs prints `is valid` and exits 0, the load
    returns `Ok`, and `virtual_net.address` is `""` — the dropped key even
    **hides** the feature-gate refusal. The canonical `[virtual_net] Address` IS
    refused (`unknown field "virtual_net.Address" … did you mean 'address'?`)
    and `[virtualNet] address` IS read, so this is specifically the alias arm;
    `normalize_client_config` canonicalises `webServer`/`featureGates`/… but not
    `virtualNet`. Pinned by
    `case_insensitive_key_in_a_table_alias_is_dropped_in_strict_mode` in
    `frp-core/src/config/tests.rs`.

  - **a nested table inside a walked section** — the key-list lookup happens for
    the *table being visited*, so a sub-table below a walked section has no list
    of its own and nothing inside it is visited either. Measured with
    `[auth.tokenSource] type = "exec"` +
    `[auth.tokenSource.exec] command = "echo tok"` and a capitalised `Env`:
    frp-rs strict `verify` now exits **1** for both spellings, but not because it
    sees the drop — the `TokenSourceExec` gate
    (`frp-core/src/unsafe_features.rs:10`, enforced by
    `validate_token_source_unsafe` in `frp-core/src/auth.rs`) is run by the shared
    load path since `3798a727` (`frp-core/src/config/file.rs`), so verify refuses
    the config *after* the walk and the spelling no longer changes its verdict;
    `--allow-unsafe TokenSourceExec` restores `is valid`/rc 0, again for both.
    The drop is therefore visible only at the parsed-value level, which is what
    the pin below asserts: with the gate allowed, `env` is read into the
    token-source struct, `Env` leaves it empty. Go refuses both spellings
    unconditionally (`unsafe feature "TokenSourceExec" is not enabled …`), and the
    daemon exits rc **3** with
    `auth.tokenSource exec blocked: TokenSourceExec not in UnsafeFeatures
    allowlist. Pass --allow-unsafe TokenSourceExec to enable.`, identical for
    `Env` and `env` (the documented `EXIT_AUTH` extension). Already
    documented in
    [§ Deployment § Dashboard Web UI](deployment.md#dashboard-web-ui)
    (`auth.tokenSource.exec.env` has no key set at `tokenSource`), and pinned by
    `case_insensitive_key_in_a_nested_table_is_dropped_in_strict_mode` in
    `frp-core/src/config/tests.rs`.

  So "the walked sections refuse" is still not the whole rule, but its second
  half is gone: the rule is now *a key is refused only where strict mode has a
  key list for the table being visited — everywhere else it is dropped silently,
  and the dropped key can change a value or hide a later refusal*.
- **Lenient mode need not end in an error.** With a `[webServer] port` present,
  frp-rs in non-strict mode drops the mis-cased top-level key and then uses the
  defaults — `ServerAddr` becomes `0.0.0.0` and `ServerPort` becomes `7000`
  where Go uses what the file says — and the domain the command is about
  (`status` here) still succeeds on `127.0.0.1:7499`. Whether the load ends in
  an error depends on which key was dropped and what the command needs next: a
  dropped `[webServer] port` surfaces as `web server port should be set …`, a
  dropped `[[proxies]] name` as `missing field \`name\``, and a dropped optional
  key as nothing at all.

Scope of what *is* matched: the exact snake_case names, plus the documented
Go camelCase aliases (`serverAddr`, `serverPort`, `webServer`, `tokenSource`,
`oidcClientId`, …) which serde accepts per struct. What is **not** matched:
arbitrary case variants of any key, at any level, on either frpc or frps. The
array-element arm of that now matches the walked sections' behaviour instead of
being an exception: with the array recursion in place a mis-cased key inside a
`[[proxies]]`/`[[visitors]]` element, a `[proxies.plugin]` table or an
`[[httpPlugins]]` entry is refused in strict mode (`unknown field
"proxies[0].RemotePort" … did you mean 'remotePort'?`, exit 1) and dropped under
`--strict-config=false`, exactly as `[webServer] Port` behaves on both sides of
the flag. The practical advice is the same as the README's: use the documented
spellings; the camelCase aliases cover the Go-authored configs. The two arms
above (`[virtualNet]`, `auth.tokenSource.exec`) remain open and are recorded in
`TODO.md`.

#### The persistent rootCmd flags on every subcommand

Go registers five flags on `rootCmd` (`cmd/frpc/sub/root.go`, `func init()`):
`-c`/`--config`, `--config-dir`, `--strict-config`, `--allow-unsafe` and
`-v`/`--version`. pflag therefore parses all five for **every** subcommand —
`frpc tcp --help` lists them under `Global Flags`, beside the command's own
flags — while the eight single-proxy commands never read any of them and the
four admin commands read only `-c`/`--strict-config`. frp-rs's bpaf parsers did
not register the flags on those twelve commands — the eight had none of the
five, and the admin four lacked `--config-dir`, `--allow-unsafe` and
`-v`/`--version` — so argv Go runs exited 1 with ``Error: `-c` is not expected
in this context`` (the analogous message per flag) and the proxy never started
(`TODO.md:4506`). All five are now registered and **dropped**: acceptance is the
parity, not the value.

Measured on Go frp **v0.71.0** darwin/arm64 with a probe listener on the
command's `--server-port` (single-proxy) or on the `[webServer] port` the `-c`
config names (admin), and a fixed `--proxy-name x` so Go passes its own
validation. "connects" means a TCP connection reached the probe port; the
single-proxy rows use `tcp`, `https` and `tcpmux` (three different local
parsers) and the CLI pins below cover all eight:

| argv fragment (appended to the command's own flags) | Go v0.71.0 | frp-rs before | frp-rs now |
|---|---|---|---|
| `-c noweb.toml` / `--config noweb.toml` | rc 1, connects (`try to connect to server...`) | rc 1, `` `-c` is not expected`` | rc 1, connects |
| `--config-dir cDir` (and a missing dir) | rc 1, connects | rc 1, `` `--config-dir` is not expected`` | rc 1, connects |
| `-c p7498.toml -c p7499.toml` | rc 1, connects (last-wins is invisible: neither is read) | rc 1, `` `-c` is not expected`` | rc 1, connects |
| `-c --strict-config=false` | rc 1, connects — pflag takes the dash-shaped token as the value | rc 1, ``-c` requires an argument `FILE`` | rc 1, connects |
| `-c missing.toml` | rc 1, connects (the file is never opened) | rc 1, `` `-c` is not expected`` | rc 1, connects |
| `--strict-config` / `--strict-config=false` | rc 1, connects | rc 1, `` `--strict-config` is not expected`` | rc 1, connects |
| `--allow-unsafe TokenSourceExec` | rc 1, connects | rc 1, `` `--allow-unsafe` is not expected`` | rc 1, connects |
| `--version` | rc 1, connects (only the root command prints a version) | rc 1, `` `--version` is not expected`` | rc 1, connects |
| any repeated `-c`/`--config-dir`/`--strict-config`/`--version`/`--allow-unsafe` | rc 1, connects (pflag: last-wins / appends, never an error) | rc 1, ``… cannot be used multiple times`` or ``… is not expected`` | rc 1, connects |
| `-c` (dangling) | rc 1, `flag needs an argument: 'c' in -c` | rc 1, `` `-c` is not expected`` | rc 1, ``-c` requires an argument `FILE`` (message shape differs, rc agrees) |

The admin commands (``verify``/`reload`/`status`/`stop`) already declared `-c`
and `--strict-config`; `--config-dir`, `--allow-unsafe` and `--version` were
added to them the same way. Measured, Go v0.71.0 with a config whose admin port
is `17498` and a second probe on the `--config-dir`'s config port:

| argv | Go v0.71.0 | frp-rs before | frp-rs now |
|---|---|---|---|
| `status -c p7498.toml --config-dir cDir` | dials `17498` | rc 1, `` `--config-dir` is not expected`` | dials `17498` |
| `reload`/`stop -c p7498.toml --config-dir cDir` | dials `17498` | same refusal | dials `17498` |
| `status -c --strict-config=false -c p7498.toml` | dials `17498` | rc 1, ``-c` requires an argument `FILE`` | dials `17498` |
| `status -c --strict-config=false` | rc 1, `open --strict-config=false: no such file or directory` | rc 1, ``-c` requires an argument `FILE`` | rc 1, reads a file named `--strict-config=false` (message shape differs) |
| `verify -c p7498.toml --config-dir cDir --allow-unsafe X --version` | rc 0, `syntax is ok` | rc 1, `` `--config-dir` is not expected`` | rc 0 |
| `status --version -c p7498.toml`, `status -v=false -c …` | parses the flag, dials `17498` | rc 1, `` `--version`/`--version` is not expected`` | parses, dials `17498` |
| `verify --config-dir cDir` (no `-c`) | rc 1, `open ./frpc.ini: no such file or directory` (`-c`'s Go default) | rc 1, ``--config-dir` is not expected`` | rc 1, ``expected `--config=FILE``` — the pre-existing "frp-rs `verify` has no default config" divergence, now visible through this argv |

**The `-c <dash-value>` rewrite.** pflag consumes the next argv token as the
value whatever it looks like. bpaf classifies tokens before anything else
(`split_os_argument`, `bpaf-0.9.27/src/arg.rs:118-215`, then
`disambiguate_short`, `bpaf-0.9.27/src/args.rs:183-250`): `--long` is
`Arg::Long`; a single-dash token is `Arg::Short` when it has one character, when
the character after the first is `=`, or when its first character is a short the
parser registers; and only an unknown multi-character single-dash token falls
back to `Arg::Word`. `State::take_arg`
(`bpaf-0.9.27/src/args.rs:670-694`) accepts only the `Word`/`ArgWord` items
tokenisation produced, so **it is not true that bpaf never takes a
`-`-prefixed value** — measured at the base head (`ec82a20`, and re-measured at
this branch's base `f5437e6`), it already took `-foo.toml`, `-nonexistent.toml`
and `-=v` (unknown multi-character tokens are demoted to `Arg::Word`), and
refused only the flag-shaped `--strict-config=false`, `-x`, `-c`, `-a=b` and
`--long`. A shared pre-parse pass (`prepared_cli_argv` →
`rewrite_config_dash_values`, `frp-core/src/cli.rs`) therefore rewrites exactly
the config-selecting occurrences — `-c`, `--config`, `--config-dir`, the frp-rs
`--config_dir` alias — whose next token starts with `-` into the attached
`-c=VALUE` spelling before bpaf sees argv. Both entry points call that one
function (`parse_frps_args` and `parse_frpc_args` differ only in which parser
they run over the result), which is what makes one rule cover both binaries. For
the already-working shapes the rewrite is a pass-through pin, not a repair. It
stops at the first real `--` (Go treats everything after it as positional), and a
`--` consumed as `-c`'s value is attached like any other value. No other
value-taking flag is rewritten, so this does not claim pflag's rule as a class.

**`frps` is the same rule and is fixed too.** Measured on Go frps v0.71.0
(darwin/arm64, bounded children) against the frp-rs `frps` with the shared pass;
the "before" column was re-measured with the source reverted to the base head
(`f5437e6`), not quoted from an earlier round:

| argv | Go v0.71.0 | frp-rs before | frp-rs now |
|---|---|---|---|
| `frps -c --strict-config=false` | rc 1, `open --strict-config=false: no such file or directory` | rc 1, ``-c` requires an argument `FILE`` | rc 1, same load path: `--strict-config=false: failed to read config file: No such file or directory (os error 2)` (the line is bare on stdout since the output-shape round; message shape differs from Go's, but rc and the *named path* agree) |
| `frps -c -x` | rc 1, `open -x: no such file or directory` | rc 1, ``-c` requires an argument `FILE`, got a flag `-x`, try `-c=-x` …`` | rc 1, same load path naming `-x` |
| `frps -c --bind-port` (a *known* frps flag) | rc 1, `open --bind-port: no such file or directory` | rc 1, ``-c` requires an argument `FILE`, got a flag `--bind-port` …`` | rc 1, same load path naming `--bind-port` |
| `frps -c --` | rc 1, `open --: no such file or directory` — pflag takes the separator token as the value | rc 1, ``-c` requires an argument `FILE`` | rc 1, same load path naming `--` |
| `frps -c -zzz` (unknown multi-character token) | rc 1, `open -zzz: …` | rc 1, same load path (bpaf already took it as `Arg::Word`) | rc 1, unchanged |
| `frps -c -` | rc 1, `open -: …` | rc 1, same load path | rc 1, unchanged |
| `frps --config -x` | rc 1, `open -x: …` | rc 1, ``--config` requires an argument `FILE`, got a flag `-x` …`` | rc 1, same load path naming `-x` |
| `frps --config=-x`, `frps -c=-x`, `frps -c=-nonexistent.toml` | rc 1, `open -x` / `-nonexistent.toml: …` | rc 1, same load path | rc 1, unchanged (attached spellings never needed the rewrite) |
| `frps -- --strict-config=false` / `frps -- -c p.toml` | **starts the server** — `frps -p <free> -- --strict-config=false` is `frps started successfully`, alive at 5 s (killed); cobra takes everything after `--` as positional args and `frps`'s `RunE` ignores them | rc 1, `` `--strict-config=false` is not expected in this context`` | rc 1, unchanged — the rewrite stops at a real `--`; **the divergence is "Go serves vs frp-rs refuses"**, not the message shape. `unknown command "…"` fires only for a positional **without** `--` (`frps junk`, `frps -c <valid> junk`, `frps --strict-config false` — all rc 1, measured) |
| `frps -c` (dangling) | rc 1, `flag needs an argument: 'c' in -c` | rc 1, ``-c` requires an argument `FILE`` | rc 1, unchanged (message shape differs, rc agrees) |
| `frps -c --help` | rc 1, `open --help: no such file or directory` (`--help` is `-c`'s value, so it is never seen as the help flag) | rc 0, prints help | rc 1, load path naming `--help` — a match; the old `rc 0` convenience is deliberately gone |
| `frps -c a.toml -c b.toml` (repeated) | rc 1, `open b.toml: …` — pflag is **last-wins** and starts with a valid `b` | rc 1, ``argument `-c` cannot be used multiple times in this context`` | rc 1, unchanged — **frps has no last-wins at all**, on either tree; only the frpc `-c` work uses `.last()`. The dash-valued repeat (`-c --strict-config=false -c p.toml`) moves from the `-c` refusal to this same message (rc 1 either way) |
| `frps --config-dir --strict-config=false` / `--config_dir --strict-config=false` | rc 1, `unknown flag: --config-dir` / `unknown flag: --config_dir` — Go frps has **no** such flag | rc 1, ``--config-dir` requires an argument `DIR`` | **rc 2**, `Failed to read config directory: No such file or directory (os error 2)`: `--config-dir` is an frp-rs extension and one of the four flags the pass covers, so the dash-shaped token is now its value and the directory read runs; the extension's refusal stays on `EXIT_CONFIG`/2 (see § CLI exit codes). Still divergent from Go in a different way, and not comparable — Go has no flag to compare against |
| `frps verify -c --strict-config=false` | rc 1, `open --strict-config=false: no such file or directory` (Go has `frps verify`) | rc 1, ``-c` requires an argument `FILE`` | rc 1 on **stdout**: `--strict-config=false: failed to read config file: No such file or directory (os error 2)`. `frps verify` is a real subcommand now, so the first error is the config read — the flip this cell predicted when the subcommand landed. rc, stream and the named path agree with Go; the wording is frp-rs's. Pinned by the **re-pointed** `verify_subcommand_resolves_so_the_dash_config_value_is_the_first_error` |

Scope note: `--config-dir`/`--config_dir` are not Go `frps` flags at all (Go:
`unknown flag: --config-dir`, rc 1), so the pass covering them on `frps` is an
frp-rs-internal consistency choice, not a parity claim: the same flag behaves the
same way on both frp-rs binaries. A `-`-prefixed token after any *other* flag
(`--bind-port -x`, `-t -x`) is untouched, and a token after a real `--` is never
rewritten.

#### A subcommand after leading root flags (cobra's command resolution)

Go's cobra resolves a command that follows leading root flags, because `Find`
(`cobra-1.8.0/command.go`, reached from `ExecuteC`) strips flags with
`stripFlags` and then looks at the **first surviving bare word**: if that word
names a child command, the child is selected and `argsMinusFirstX` removes it
before the child's pflag parse. bpaf instead picks a branch *before* dispatch,
so `frpc -c pA.toml status` used to fall through to run mode and answer rc 1
``Error: no such command or positional: `status`, did you mean `https`?``.
`frp-core/src/cli.rs`'s `hoist_leading_subcommand` now moves that token to the
front of the argv before bpaf runs (`TODO.md:4710`).

Composition, because it is load-bearing: the entry points call `cli_args`
(which drops `argv[0]` and expands the `-v=` alias), then `prepared_cli_argv`,
which applies `rewrite_config_dash_values` **first** and
`hoist_leading_subcommand` **second**. **Both binaries run the hoist**; which
root command's command-and-bool-flag sets it reads is `RootCommand`
(`frp-core/src/cli.rs`), because those are exactly the two facts cobra's
`stripFlags` and `Find` read and they differ per binary. The sentence this
paragraph used to carry — "`frpc` only (`has_subcommands`; Go's `frps` declares
no subcommands, so its behaviour is byte-identical to before)" — was **false**:
Go's `frps` registers `verify` on `rootCmd` (`cmd/frps/verify.go:29`) beside
cobra's `completion` and `help`, and `frps --help` lists all three (measured), so
`frps` runs the same resolution. The `frps` rows are further down this section.
The rewrite must run first because the hoist classifies flag/value/bare-word the
way cobra does, and cobra classifies the argv pflag has already applied its
value rule to. The shape that shows it: `-c -- status`, where the value of `-c`
is the token `--` itself, so `status` is the first bare word and Go resolves the
`status` command (measured: rc 1 `open --: no such file or directory` — the
config read happens on the admin path). Hoisting on the raw argv would see a
`--` separator there and leave the token behind.

Measured on Go frp **v0.71.0** darwin/arm64 against the frp-rs `frpc` at this
branch's base (`5b9a084`) and head, with the port the config names held by a
one-shot mock admin listener (a single JSON `{}` answer) or, for the
single-proxy rows, a canary TCP listener on `--server-port`. "dials N" means the
listener accepted a connection and the request/`Host:` named N; a `rc 1` cell
with no dial is a refusal before any connection.

| argv | Go v0.71.0 | frp-rs before | frp-rs now |
|---|---|---|---|
| `-c pA.toml status` | rc 0, dials the config's admin port, `Proxy Status...` | rc 1, ``no such command or positional: `status`, did you mean `https`?`` | rc 0, dials it |
| `--strict-config=false status -c pA.toml` | rc 0, dials it | rc 1, same refusal | rc 0, dials it |
| `-c pA.toml --strict-config=false status` | rc 0, dials it | rc 1, same refusal | rc 0, dials it |
| `-c pA.toml -c pA.toml status` (repeated) | rc 0, dials it | rc 1, same refusal | rc 0, dials it |
| `--allow-unsafe TokenSourceExec -c pA.toml status`, `-v=false … status`, `--version=false … status`, `--version=true … status`, `--config-dir <dir> -c pA.toml status`, `-c pA.toml --strict-config=false --allow-unsafe TokenSourceExec status` | rc 0, dials it | rc 1, same refusal | rc 0, dials it |
| `-c=pA.toml status`, `-cpA.toml status`, `-c pA.toml --config=pA.toml status` | rc 0, dials it | rc 1, same refusal | rc 0, dials it |
| `-c missing.toml tcp --local-port 5 --remote-port 6 --proxy-name x --server-port <free>` | rc 1, **connects** (`try to connect to server...`, then the probe's non-TLS bytes) — the missing config is never opened | rc 1, ``no such command or positional: `tcp`, did you mean `stcp`?`` | rc 1, connects the same way |
| `-c missing.toml https` | rc 1, `name should not be empty` (the `https` branch runs; its `--custom-domains` is required) | rc 1, ``no such command or positional: `https`, did you mean `http`?`` | rc 1, ``expected `--local-port=PORT` `` — the **branch is the same one**, but bpaf reports its first missing flag where Go reports a later validation. Recorded, not claimed as a match |
| `-c pA.toml -- status` | rc 1, starts the client in **run mode** (`start frpc service for config file […/pA.toml]`), never dials the admin port | rc 1, `` `status` is not expected in this context`` | unchanged — a real `--` stops the hoist; the positional refusal is the recorded divergence below |
| `-c pA.toml -- notacommand status` | rc 1, run mode, same as above | rc 1, `` `notacommand` is not expected`` | unchanged |
| `-c status` / `--config status` / `--config=status` / `-c=status` / `-cstatus` — a config file **literally named `status`** | rc 1, run mode (`start frpc service for config file […/status]`), never the admin command | rc 1, run mode, same message | unchanged — the token is `-c`'s value |
| `-c -status` | rc 1, `open -status: no such file or directory` | rc 1, same load path, message shape differs | unchanged |
| `-c --strict-config=false` (no subcommand) | rc 1, `open --strict-config=false: …` | rc 1, same load path | unchanged |
| `-c -- status` | rc 1, `open --: no such file or directory` — `--` is `-c`'s value, so `status` **is** resolved | rc 1, ``no such command or positional: `status` `` | rc 1, `--: failed to read config file: …` — Go's path; a match on rc and on both behaviours, message shape aside |
| `tcp --proxy-name status --local-port 5 … --server-port <free>` | rc 1, connects (the proxy starts with a proxy named `status`) | rc 1, connects | unchanged |
| `-c missing.toml tcp --proxy-name status …` | rc 1, connects | rc 1, ``no such command or positional: `tcp` `` | rc 1, connects |
| `tcp --proxy-name=status …` | rc 1, connects | rc 1, connects | unchanged |
| `-c pA.toml notacommand` | rc 1, `unknown command "notacommand" for "frpc"` | rc 1, `` `notacommand` is not expected in this context`` | unchanged (message shape) |
| `-c pA.toml notacommand status` | rc 1, same — the first bare word is the only candidate | rc 1, same refusal | unchanged |
| `-c pA.toml reload` / `stop` / `verify` | rc 0 `reload success` / `stop success`; `verify` rc 1 on a missing file | rc 1, `` `reload` is not expected in this context`` (per command) | rc 0 / rc 1, the same commands |
| `status -c pA.toml` (frp-rs's own order), `status -c pA.toml --strict-config=false` | rc 0, dials it | rc 0, dials it | unchanged (regression pin) |

Two Go behaviours in the table are worth stating rather than assuming. First,
`--status` (a double-dash token after `-c`) is `-c`'s **value** on Go, and the
later `-c pA.toml` overwrites it — the code that made the rewrite run first.
Second, `https` after `-c missing.toml`: Go resolves the branch and fails on its
required `--custom-domains` with `name should not be empty`, while frp-rs's
`https` branch reports its first missing flag (`--local-port`); the branch is
now the same one, the message is not, and that message-shape difference belongs
to the output-shape item rather than to this one.

**Which tokens a flag swallows — `--strict-config` is the sharp case.** The
hoist has to reproduce cobra's `stripFlags`, whose rule is `hasNoOptDefVal`:
a `--long` (or two-character `-x`) without `=` consumes the next token **unless
the flag's pflag registration carries a `NoOptDefVal`**, which every bool has
(`pflag-1.0.5/bool.go:56`). On `frpc` that exempts exactly two root flags,
`--version`/`-v` (`cmd/frpc/sub/root.go:52`) and
`--strict-config`/`--strict_config` (`:53`,
`BoolVarP(&strictConfigMode, "strict_config", "", true, …)`); the three
value-taking root flags (`:50-51,55`) and any flag cobra does not know consume.
`--help`/`-h` is the counter-intuitive one and it is **not** exempt: pflag makes
`help` a bool, but cobra registers it in `execute` (`cobra-1.8.0/command.go:885`),
which `ExecuteC` calls *after* `Find` (`:1090`) ran `stripFlags` (the only other
registration site is `getCompletions`, `cobra-1.8.0/completions.go:304`, reached
only by `__complete`), so at stripping time it is unknown, `hasNoOptDefVal`
returns false, and it **does** consume the next token. Two measurements
discriminate the mechanism rather than just the outcome: `frpc --help status`
prints the **root** help (`Usage: frpc [flags]` + `Available Commands`), not the
`status` help a non-consuming flag would select (`frpc status --help` is
`Overview of all proxies status`), and `frpc --help notacommand` is rc **0** with
the same root help where a non-consuming flag would leave `notacommand` as the
first bare word for `legacyArgs` to refuse. Exempting `--help` would therefore
make frp-rs print the *status* help for `--help status`; it stays a consumer.

The first version of this pass listed `--strict-config` as a consumer, and both
directions were measured wrong. Over-consuming is not the safe direction: it
shifts *which* token is the first bare word, so it can hoist a later word cobra
would have refused.

| argv | Go v0.71.0 | frp-rs before | frp-rs now |
|---|---|---|---|
| `--strict-config status -c pA.toml`, `--strict_config status -c pA.toml` | rc 0, dials the admin port (`status` was not consumed) | rc 1, ``no such command or positional: `status` `` | rc 0, dials it |
| `-c pA.toml --strict-config status`, `-c pA.toml --strict_config status` | rc 0, dials it | rc 1, same refusal | rc 0, dials it |
| `--strict-config tcp --local-port 5 … --server-port <free>` | rc 1, **connects** (the tcp branch runs) | rc 1, ``no such command or positional: `tcp` `` | rc 1, connects |
| `--strict-config reload -c pA.toml` | rc 0, `reload success` | rc 1, `` `reload` is not expected `` | rc 0 |
| `--strict-config verify -c missing.toml` | rc 1, `open …missing.toml: no such file or directory` (the verify branch runs) | rc 1, `` `verify` is not expected `` | rc 1, the config-load error |
| `--strict-config true status -c pA.toml`, `--strict-config false status -c pA.toml`, `--strict_config true stop -c pA.toml`, `--strict-config true reload -c pA.toml` | rc 1, ``unknown command "true"/"false" for "frpc"`` — the word is the first bare word and **no** command is resolved | rc 1 (a different refusal) | rc 1, no dial — the same outcome as Go |
| `--strict-config true {tcp,udp,http,https,stcp,xtcp,sudp,tcpmux} … --server-port <free>` — **all eight single-proxy branches** | rc 1, ``unknown command "true"``, nothing dialled | rc 1, same class | rc 1, nothing dialled |
| `--strict-config true {status,stop,reload} -c pA.toml` — the three admin commands | rc 1, ``unknown command "true"``, no admin request | rc 1, same class | rc 1, nothing dialled |
| `--strict-config=true status -c pA.toml`, `--strict-config=false status -c pA.toml` | rc 0, dials it | rc 1, the refusal | rc 0, dials it (unchanged by this fix: the `=` form never consumed) |
| `--strict-config=foo status -c pA.toml` | rc 1, pflag's `invalid argument "foo" for "--strict-config" flag: strconv.ParseBool: …` | rc 1, bpaf's message | rc 1, unchanged (message shape differs) |
| `status --strict-config false -c pA.toml` (space form **after** the command) | rc 0, dials it (`false` is ignored as a positional) | rc 0, dials, prints the space-form warning | unchanged |
| `--strict-config notacommand status` | rc 1, `unknown command "notacommand"` | rc 1, leftover-token refusal | unchanged (message shape) |
| `--strict-config true` (no command) | rc 1, `unknown command "true"` | rc 1, config-load error | unchanged |

The other four root flags were swept the same way and are **correct**: with
`--allow-unsafe TokenSourceExec status -c pA.toml`, `--config-dir <dir> status
-c pA.toml`, `--version status -c pA.toml` and `-v status -c pA.toml` Go dials
the admin port and so does the head (rc 0); `--allow-unsafe status -c pA.toml`
consumes `status` as the flag's value on **both** (rc 1, run mode, no dial);
`--help status` and `-h status` print help on both (rc 0). The single-proxy and
run-only frp-rs flags (`--log-level`, `--disable-log-color`) are treated as
value-taking, which matches cobra's treatment of them as *unknown* flags
(measured: `--disable-log-color status` is rc 1 on Go and here, no dial).

**Blast radius of the direction-A bug, measured on all eleven commands.** R2's independent
sweep first found the class wider than the `tcp` row above: every one of the eight single-proxy
branches connected to the `--server-port` canary on the pre-fix head — `tcp`, `udp`, `http`,
`https`, `stcp`, `xtcp`, `sudp`, `tcpmux`, each with its own required flags — and the three
admin commands (`status`, `stop`, `reload`) returned rc 0 with a real request to the mock
(`GET /api/status`, `POST /api/stop`, `POST /api/reload`). Re-measured here on Go / base /
pre-fix head / fixed with one row per command (`/tmp/ledprobe/{go,base,oldhead,fixed}_sc8.jsonl`,
11 rows each): all eleven rows have the pre-fix head differing from Go on (rc, dial), and the
fixed head agrees with Go on all eleven. So the hole was "any command resolved from a word that
followed the bare bool", not a `tcp`-specific one.

**Not hoisted, deliberately.** A leading token that merely starts with a dash is
never a candidate, and only the **first** bare word can be one: cobra's `Find`
looks at `argsWOflags[0]` and `legacyArgs` refuses that word even when a real
command name follows it, so `notacommand status` is Go's
`unknown command "notacommand"` (measured). The `nathole` command Go lists is not
implemented, so `frpc -c cfg.toml nathole` stays a leftover-token refusal;
`completion` and `help` are cobra built-ins and are not implemented either —
both are deliberately absent from `FRPC_SUBCOMMANDS`, which is pinned against
`frpc_parser` in both directions by unit tests.

Four residual rows, each measured and each **pre-existing** (the base behaves the
same as the head):

* `frpc - status` and `frpc -c pA.toml - status`: Go resolves `status` and
  ignores the stray `-` positional (`frpc - status` is rc 1 only because the
  status command's default config `./frpc.ini` is missing; `-c pA.toml`
  variants are rc 0 and dial). The hoist resolves the command correctly and then
  bpaf refuses the leftover `-` — the positional-arguments divergence below, not
  a command-resolution one.
* `frpc --config-dir <empty or non-dir>`: Go rc 0 (its `runMultipleClients`
  swallows the error), frp-rs rc 2 — the deliberate directory-mode divergence in
  § CLI exit codes.
* `frpc status -c pA.toml stop`: the first subcommand is already selected, so the
  later word is a positional; Go ignores it (rc 0), frp-rs refuses it (rc 1).
  Same positional rule.
* `frpc -c pA.toml nathole`, `completion`, `help` as a bare word: Go rc 0
  (`nathole` is a real command there and the other two are built-ins), frp-rs
  rc 1 — the implementation gap named above.

**What remains divergent, with its measurement.** (1) Positional arguments, as
described above: Go ignores them, frp-rs refuses a leftover token, with or
without `--` — `frpc status -c p7498.toml -- -c p7499.toml` dials 7498 on Go and
is rc 1 here. The rewrite adds one instance of the same rule: when the value
consumed for `-c` is itself flag-shaped, the flag's **own** argument is left
behind as a positional Go ignores and frp-rs refuses — measured, `frpc tcp …
-c --config-dir cDir` reaches `try to connect to server...` on Go and is rc 1
`` `cDir` is not expected`` here; `frpc status -c --config-dir cDir` is Go
`open --config-dir` (rc 1) vs rc 1 `` `cDir` is not expected``; `frpc tcp …
-c --strict-config false` starts on Go and is rc 1 `` `false` is not expected``
here. (2) The *message* on a rejected value: `frpc tcp … --strict-config=foo`
is pflag's `invalid argument "foo" for "--strict-config" flag: strconv.ParseBool:
…` on Go and `` `foo` is not expected in this context `` here; both exit 1, and
that shape is the already-recorded output-shape item, not this one. (3) A
config *load* failure reached **stderr** through `verify` only at the head this
rewrite landed on; measured then, `reload`/`status`/`stop -c <unknown-key
config>` all wrote the same error to **stdout**, matching Go's stream. **That is
no longer a divergence**: the output-shape round moved `verify` to stdout too,
so all four subcommands now print the load error on the stream Go uses (the
message *shape* still differs — see
[§ Output stream and shape on a config-load failure](#output-stream-and-shape-on-a-config-load-failure)).
(4) `help` routing, a consequence of the
rewrite and of pflag's value rule: `frpc -c --help` / `frpc --config --help`
printed help (rc 0) at the base head and now read a config called `--help`
(rc 1), which is what Go does (`open --help: no such file or directory`), and on
a single-proxy command `frpc tcp … -c --help` now starts the proxy instead of
printing help, again as Go. `frpc --config-dir --help` is the one that moves
*away*: rc 0 help at the base head, **rc 2** now, because the value reaches the
pre-existing frp-rs `--config-dir` refusal (Go swallows the `WalkDir` error and
exits 0 — the recorded "Directory mode is a deliberate divergence" in § CLI exit
codes). The bare-run spelling `frpc --config-dir -x -c <cfg>` moves rc 1 → 2 for
the same reason. This is the frp-rs `--config-dir` extension's territory, not a
persistent-flag claim.

Pinned by `every_single_proxy_command_ignores_all_five_persistent_root_flags`,
`repeated_persistent_root_flags_are_not_an_error`,
`a_dash_prefixed_value_after_c_is_the_config_value`,
`config_dir_is_ignored_by_the_admin_subcommands`,
`verify_accepts_the_root_flags_it_ignores`,
`dangling_config_flag_and_bad_bool_value_still_fail` and
`positional_arguments_are_still_refused` in `frpc/tests/cli_persistent_flags.rs`
(6 of the 7 fail at the base head; the positional one passes on both trees by
design), plus the parser-level tests in `frp-core/src/cli.rs`
(`every_single_proxy_command_accepts_the_five_persistent_root_flags`,
`tcp_config_flag_value_is_parsed_and_dropped`,
`persistent_root_flags_tolerate_pflag_repetition`,
`admin_subcommands_accept_the_root_flags_they_did_not_declare`,
`strict_config_value_grammar_is_still_go`, `single_proxy_help_lists_the_global_flags`,
`rewrite_attaches_a_dash_prefixed_config_value`,
`rewrite_leaves_every_other_shape_alone`).

**The `frps` rows of the same resolution, measured separately.** They are
separate numbers because the frps base is a different tree (`37f91cd`) and its
root command's flag set is not frpc's. Every row below was run with its own valid
config and its own free port, stdout and stderr redirected to separate files, the
exit status read directly from the child, and every child bounded (6 s) and
reaped. `frps` has one child command — `verify` — so every row asks the same
question: does the first surviving bare word become that command?

| argv | Go v0.71.0 | frp-rs before (`37f91cd`) | frp-rs now |
|---|---|---|---|
| `frps verify -c good.toml` | rc 0, `frps: the configuration file good.toml syntax is ok` | rc 1, `` `verify` is not expected in this context`` | rc 0, the same line |
| `frps -c good.toml verify` | rc 0, same line (`-c` consumes its value, `verify` is the first bare word) | rc 1, the same refusal | rc 0, resolved by the hoist |
| `frps --strict-config=false verify -c good.toml` | rc 0, same line | rc 1, the same refusal | rc 0, resolved by the hoist |
| `frps --strict_config=false verify -c good.toml` | rc 0 (the `_` spelling is the same pflag) | rc 1, the same refusal | rc 0 |
| `frps --strict-config=false verify -c bad.toml` (unknown key) | rc 0, `syntax is ok` — lenient | rc 1, the refusal | rc 0, lenient |
| `frps --tls-only verify -c good.toml` | rc 0, `syntax is ok` (`--tls-only` is a pflag **bool**: it does not consume `verify`) | rc 1, the refusal | rc 0 |
| `frps --enable-prometheus verify -c good.toml`, `frps --disable-log-color verify -c good.toml` | rc 0, same (both are `BoolVarP`) | rc 1, the refusal | rc 0 |
| `frps --version verify -c good.toml` | rc 0, `syntax is ok` — **no version line**: `showVersion` is read only by the root command's `RunE` (`cmd/frps/root.go:57`), never by `verifyCmd` | rc 1, the refusal | rc 0, no version line |
| `frps -p <free> verify -c good.toml` | rc 0 — `-p` consumes its port, `verify` is the *next* token and is the first bare word | rc 1, the refusal | rc 0 |
| `frps --dashboard-tls-mode verify -c good.toml` | **rc 143** — the probe's 6 s SIGTERM watchdog killed a server that had **started** (`frps started successfully`; the `timeout`-based rows elsewhere in this file report 124 for the same shape). `--dashboard-tls-mode` is registered with `VarP(BoolFuncFlag{…})` (`pkg/config/flags.go:256-258`), **not** `BoolVarP`, so pflag never sets `NoOptDefVal` on it and it consumes `verify` as its value — no bare word survives | rc 1, the refusal | rc 1, `` `verify` is not expected in this context`` — **still divergent**: the hoist correctly declines to move the token (the row above is why), but frp-rs models the flag as a bool, so it has no value slot to put `verify` in. The divider is "Go serves, frp-rs refuses"; the pre-existing `--dashboard-tls-mode` modelling divergence, not a command-resolution one |
| `frps --strict-config true verify -c bad.toml` | rc 1 on **stderr**, ``Error: unknown command "true" for "frps"`` — pflag's bool does not consume `true`, so `true` is the first bare word and cobra refuses it instead of resolving `verify` | rc 1, `` `verify` is not expected`` | rc 1, `` `verify` is not expected in this context`` — same rc, same (empty) stdout, different message. The hoist declines for the right reason (the first bare word is `true`, not a command); the leftover frp-rs reports is `verify`, because its space-form `--strict-config true` *does* consume `true` (the documented extension below). The `unknown command "…"` message shape is the pre-existing divergence recorded in § `--strict-config` |

The last two rows are the reason the classification is per root command and not a
shared constant. Go's `frps` root registers **five** pflag bools — `version` and
`strict_config` (`cmd/frps/root.go:44-48`) plus `enable_prometheus`,
`disable_log_color` and `tls_only` (`pkg/config/flags.go:242,246,251`) — against
`frpc`'s two, and it registers `dashboard_tls_mode` as a *consumer* even though
it reads like the others. Getting that backwards is observable in both
directions: treating `--dashboard-tls-mode` as a bool would hoist `verify` out of
an argv where Go starts a server, and treating `--tls-only` as a consumer would
leave `frps --tls-only verify -c cfg` refused where Go verifies. Both sets and
both boundaries are pinned by
`the_bool_root_flag_sets_are_per_root_command` and
`frps_hoists_verify_past_its_own_root_flags` (`frp-core/src/cli.rs`), and the
end-to-end rows by `verify_resolves_leading_root_flags_and_ignores_the_rest`
(`frps/tests/cli_exit_codes.rs`).

#### `frps verify` (Go's `verifyCmd`)

Go has had `frps verify` all along; frp-rs had no such subcommand, so
`frps verify -c frps.toml` on a **valid** config exited 1 with ``Error: `verify`
is not expected in this context`` and a script that validates a server config
with Go's command could not use frp-rs at all (`TODO.md`, "Go has `frps verify`,
frp-rs has no `frps verify` at all"). It exists now, and it is Go's command
(`cmd/frps/verify.go`): `LoadServerConfig(cfgFile, strictConfigMode)`, then
`fmt.Println(err); os.Exit(1)` on failure, and
`frps: the configuration file %s syntax is ok` on success — on **stdout**, which
is where the client's `verifyCmd` writes too
(`cmd/frpc/sub/verify.go:59,63`).

Measured on Go v0.71.0 darwin/arm64 and on the frp-rs debug binary at `37f91cd`
(before) and at the head (after), streams captured separately and the exit status
read directly from the child, one fresh config and one fresh free port per row;
every child bounded and reaped.

| argv | Go v0.71.0 | frp-rs before | frp-rs now |
|---|---|---|---|
| `frps verify -c <valid>` | rc **0**, stdout `frps: the configuration file <path> syntax is ok`, stderr 0 B | rc 1, `` `verify` is not expected`` on stderr | rc 0, the same line, stderr 0 B |
| `frps verify -c <missing>` | rc **1**, stdout `open <path>: no such file or directory`, stderr 0 B | rc 1, the refusal | rc 1, stdout `<path>: failed to read config file: No such file or directory (os error 2)`, stderr 0 B — same rc, same stream, same named path; the wording is frp-rs's |
| `frps verify -c <unknown key>` (strict default) | rc **1**, stdout `json: unknown field "notAKnownFrpKey"`, stderr 0 B | rc 1, the refusal | rc 1, stdout `unknown field "notAKnownFrpKey" in config file <path>`, stderr 0 B |
| `frps verify -c <bindPort = "not-a-port">` | rc **1**, stdout `field "bindPort": cannot unmarshal string into int`, stderr 0 B | rc 1, the refusal | rc 1, stdout `<path>: config validation error: invalid type: string "not-a-port", expected u16`, stderr 0 B |
| `frps verify` (no `-c`) | rc **0**, stdout `frps: the configuration file is not specified`, stderr 0 B — Go's `-c` default is the **empty string** on `frps` (`cmd/frps/root.go:44`) and `verifyCmd` returns nil for it (`cmd/frps/verify.go:36-39`) | rc 1, the refusal | rc 0, the same line. Unlike `frpc`, whose `-c` defaults to `./frpc.ini` |
| `frps verify -c <valid> --strict-config=false`, `frps verify --strict-config=false -c <valid>`, `frps --strict-config=false verify -c <valid>`, `frps --strict_config=false verify -c <valid>` | rc **0**, `syntax is ok` on all four | rc 1 (all four) | rc 0 (all four), stderr 0 B — the `=` form is Go-faithful and does not warn |
| `frps verify -c <unknown key> --strict-config` (bare), `… --strict-config=true`, `… --strict-config=false` | rc 1 / rc 0 / rc 0 — the bare and `=true` forms stay strict | rc 1 (the refusal) | rc 1 / rc 0 — same verdicts |
| `frps verify --strict-config true -c <unknown key>` (space form) | rc **1**, `json: unknown field …` — pflag's bool does not consume `true`, so strict stays at its `true` default and `true` is an ignored positional | rc 1 (the refusal) | rc **1**, the same verdict, plus the frp-rs **warning** on stderr: the space form is read as the value (the documented extension below) |
| `frps verify -c <valid> -c <valid2>` | rc **0** naming `<valid2>` — pflag is last-wins | rc 1 (the refusal) | rc 0 naming `<valid2>` |
| `frps verify --bind-port <free> -c <valid>`, `frps verify --allow-unsafe X --version -c <valid>` | rc **0**, `syntax is ok` — `verifyCmd` reads only `cfgFile` and `strictConfigMode` (`cmd/frps/verify.go:36,40`) and every other flag Go's `frps` root registers is accepted and ignored | rc 1 (the refusal) | rc 0, the same line; for the `--version` spelling that is the discriminating half — Go prints a version only from the root command's `RunE`, never here |
| `frps verify --log-format json -c <valid>` (`=json`, `--log_format json`, and the flag after `-c`) | rc **1**, stdout 0 B, stderr `Error: unknown flag: --log-format` + usage — Go **frps** has no such flag, so its `verify` refuses it | rc 1, the refusal (that binary has no `verify` at all) | rc **1**, `` `--log-format` is not expected in this context`` — **fixed in this round**: the flag used to ride into `verify` through `frps_build` and made this argv print `syntax is ok` and exit **0**, a validation command reporting success for an argv Go rejects. The run path keeps it (documented extension); pinned by `verify_refuses_the_two_frp_rs_only_root_flags_like_go` and `frps_verify_refuses_the_run_paths_extension_flags` |
| `frps verify --config-dir <dir> -c <valid>`, `frps --config-dir <dir> verify -c <valid>` (`--config_dir` too) | rc **1**, stdout 0 B, stderr `Error: unknown flag: --config-dir` + usage (Go frps has no such flag) | rc 1, the refusal | rc **1**, `` `--config-dir` is not expected in this context`` — same rc, different message; the second of the two extension slots, refused from the start for exactly the reason the `--log-format` row above now is |
| `frps verify --vhost-http-timeout 30 -c <valid>` (and the `--vhost_http_timeout` spelling) | rc **0**, `syntax is ok` (it is a Go `frps` root flag, and `verifyCmd` ignores it) | rc 1, the refusal (no `verify` subcommand) | rc **0**, the same line — **fixed in this round**: the flag used to be refused on both paths because frp-rs's `frps` did not model it. It is registered on the shared transport builder now, so the run path accepts it too (starts and listens, bounded in this harness; Go rc 124) and the rendered `--help` diff against Go has **no Go-only flag** left |
| `frps verify --dashboard-tls-mode=auto -c <valid>`, `… --dashboard-tls-mode auto -c <valid>` | rc **0**, `syntax is ok` — the flag is a **string** on Go (`VarP(BoolFuncFlag{…})`, `pkg/config/flags.go:256-258`), so `auto` is its value | rc 1, the refusal | rc **1**, `` `auto` is not expected in this context`` — **divergent, and pre-existing**: frp-rs models that flag as a bool, which is the same model divergence the run path carries (the `--flag=<bool>` table's `--dashboard-tls-mode=auto` row: Go 124, base 1, head 1) |
| `frps verify -c <valid> --dashboard-tls-mode` (trailing bare) | rc **1**, stdout 0 B, stderr `Error: flag needs an argument: --dashboard-tls-mode` + usage — a bare string flag with no value | rc 1, the refusal | rc **0**, `frps: the configuration file <valid> syntax is ok` — a **false success**, and the row that makes the "ignores every root flag" sentence wrong: frp-rs reads the bare spelling as `true`, so the flag is *not* ignored, it is misread. Same pre-existing bool-vs-string model, newly visible here; the run path accepts the bare flag too (Go rc 1 `flag needs an argument`, base and head proceed). Recorded, not pinned |
| `frps verify -c <valid> junk` | rc **0** — `verifyCmd` sets no `Args` validator, so cobra passes positionals through and the command ignores them | rc 1, the refusal | rc **1**, `` `junk` is not expected in this context`` — **divergent** (and the same divergence `frpc verify -c <valid> junk` has, measured: Go rc 0, frp-rs rc 1). Left as the pre-existing positional-arguments divergence, recorded here rather than pinned |
| `frps verify --strict-config foo -c <valid>` | rc **0** — the stray token is an ignored positional and strict stays `true` | rc 1, the refusal | rc **1**, `` `foo` is not expected`` — same class as the row above, and the same as `frpc verify --strict-config foo -c <valid>` |
| `frps verify --help` | rc 0, cobra's help for the command: `Usage: frps verify [flags]` with the whole root flag set under `Global Flags` | rc 1, the refusal | rc 0, bpaf's help for the command (`Usage: frps verify …`). The **rendering** is not Go's — the pre-existing help-shape divergence, not this command's |
| `frps help`, `frps completion` | rc 0 (cobra built-ins: `help` prints the root help, `completion` prints its own) | rc 1, the refusal | rc 1 — unimplemented, exactly as on `frpc`; `FRPS_SUBCOMMANDS` lists only `verify`, and is pinned against the parser in both directions by `the_frps_command_list_is_exactly_the_parser_branches` |

Three things this table does **not** claim:

* **The config verdict is the *load path's* verdict, and it is shared by both
  binaries.** `run_verify` (`frps/src/main.rs`, `frpc/src/main.rs`) loads through
  `load_server_config_checked` / `load_client_config_with_presence_checked`
  (`frp-core/src/config/file.rs`), which run the post-load unsafe-feature gate —
  `check_server_unsafe_features` / `check_client_unsafe_features`, on top of the
  same predicate the daemons call, `frp_core::auth::validate_token_source_unsafe`
  — before returning. The service-construction gates that live *after* the load
  (`frp-server/src/service.rs`) are still not run, so a check added only there
  would still not be visible here; the unsafe-feature gate sits on the load path
  precisely because both commands share it. Measured on Go v0.71.0 with
  `[auth.tokenSource] type = "exec"`: `frps verify -c <that config>` is rc **1**,
  stdout `unsafe feature "TokenSourceExec" is not enabled. To enable it, ensure
  it is allowed in the configuration or command line flags`, stderr 0 B
  (`ValidateUnsafeFeature`, `pkg/config/v1/validation/validator.go:22-27`, called
  for `tokenSource.Type == "exec"` at `pkg/config/v1/validation/auth.go:34-35`
  and reached from `cmd/frps/verify.go:46-48`, whose error arm is `:52-55`); the
  head is rc **1** as well, but prints its own one-line message, because the
  predicate's wording is frp-rs's — the divergence is in the text, not the
  verdict. `--allow-unsafe TokenSourceExec` makes both rc 0, and a wrong value is
  fail-closed on both. One deliberate difference remains: Go's **run** path
  refuses the same config with rc 1 while frp-rs's daemon exits 3 `EXIT_AUTH` —
  the documented `EXIT_AUTH` extension, unchanged by this round and stated in the
  pins' doc tables.
* **The two frp-rs-only extensions are refused, but the run path still accepts
  both.** `frps --config-dir <dir>` is rc 2 on that path and rc 1
  `unknown flag` on Go; `frps --log-format json -c <cfg>` is accepted on that
  path and rc 1 `unknown flag` on Go. The verify subcommand takes the Go-side
  answer for both. Measured, the extension set is complete: diffing the rendered
  `--help` flag lists of the two binaries gives **frp-rs-only = {`config-dir`,
  `log-format`}** and **Go-only = {}** — the `--vhost-http-timeout` row
  above closed the last Go-only flag.
* **"Every other root flag is accepted and ignored" is true of Go and nearly so
  of frp-rs; the exception is named rather than rounded away.** For Go the
  sentence needs one carve-out: `verifyCmd` itself reads two fields (`cfgFile`,
  `strictConfigMode`) and every other flag it declares is inert, but
  `--allow-unsafe` is consulted one level down by the post-load unsafe-feature
  gate (`ValidateServerConfig`) — measured on v0.71.0, `frps verify -c <exec
  tokenSource cfg>` is rc 1 without it and rc 0 with `--allow-unsafe
  TokenSourceExec` (the rows the bullet above measures). frp-rs's `verify` reads
  the same three fields — `cfgFile`, `strictConfigMode` and `--allow-unsafe`
  (`VerifyArgs` in `frp-core/src/cli.rs`) — and the precise claim is "every root
  flag frp-rs **models**"; the surviving exception is a flag frp-rs models as a
  different *kind*: `--dashboard-tls-mode` (a string on Go, a bool here) is
  refused in the `=auto`/space spellings and **read as `true`** in the bare
  trailing spelling — which Go answers with `flag needs an argument` and frp-rs
  answers `syntax is ok`, rc 0. That row is a false **ok**, not an ignore, and it
  is why the sentence in `frp-core/src/cli.rs` and `CHANGELOG.md` says "every
  root flag frp-rs models". The other exception this bullet used to name — a
  flag frp-rs did not model at all, `--vhost-http-timeout` — is registered and
  no longer applies.
* **The `frps -c a.toml -c b.toml` run-path divergence is untouched.** That path
  still has no last-wins (its `-c` is [`svr_config`], not `config_arg`), while
  `verify`'s `-c` is `config_arg` — pflag last-wins — because Go's `verifyCmd`
  reads the same persistent `StringVar`. The two are separate surfaces and the
  run path's row is unchanged by this work.

Pinned by `verify_valid_config_prints_go_line_and_exits_0`,
`verify_invalid_config_exits_1_with_the_load_error_on_stdout`,
`verify_missing_config_exits_1_naming_the_path`,
`verify_without_a_config_file_is_not_an_error`,
`verify_strict_config_false_is_lenient_in_every_flag_order`,
`verify_strict_config_true_still_refuses_the_unknown_key` and
`verify_resolves_leading_root_flags_and_ignores_the_rest` in
`frps/tests/cli_exit_codes.rs`, plus the parser-level
`the_frps_command_list_is_exactly_the_parser_branches`,
`the_hoisted_frps_argv_parses_as_verify` and the extended
`--strict-config` table (`frps verify` is now one of its seven parsers) in
`frp-core/src/cli.rs`.

#### `--strict-config`: the space-separated value form

`--strict-config false` (a space, two argv tokens) is an **frp-rs extension**,
kept, documented and made **loud** rather than dropped (`TODO.md:3366`). Go frp
v0.71.0 registers `strict_config` as a pflag bool on both binaries, and a pflag
bool never consumes a following token — so the same argv behaves differently.
The `=` spelling (`--strict-config=false`) is the **Go-faithful** one and is the
spelling to use when an argv must behave identically under both binaries.

The extension is announced on **stderr**, once, on the path only:

```text
warning: --strict-config <bool> is an frp-rs extension; Go's pflag does not consume the token and stays strict. Use --strict-config=<bool> for identical behaviour.
```

It fires for the space-separated form on all six parsers (`frps`, and `frpc`'s
`run`/`verify`/`reload`/`status`/`stop`) and for nothing else: not the `=` form,
not the bare switch, not an absent flag, and not a non-bool token (there no value
is consumed and the parse fails before the warning point — the entry points print
it only after a successful parse). The reason it exists at all is that the
divergence is otherwise **silent**: `frpc verify --strict-config false -c
<config with an unknown key>` exits **0** where Go exits 1, and the admin
commands dial a config Go would have refused. Documentation alone never surfaces
at the moment it bites.

Measured 2026-09-26 against Go frp **v0.71.0** (darwin/arm64,
`/private/tmp/frp_0.71.0_darwin_arm64/`) and the frp-rs `frpc`/`frps` at this
branch's head. Client config: a valid config plus `notAKnownFrpKey = 1` and
`[webServer] port = 7499`, so "strict" (refuse the unknown key) and "lenient"
(dial `7499`) are distinguishable; a second client config `host.toml` has
`[webServer] addr = "localhost"` and no unknown key; server configs are
`/private/tmp/goprobe/badfrps2.toml` (`bindPort = 7511`, `auth.token`, the same
unknown key) and `/private/tmp/goprobe/goodfrps.toml` (`bindPort = 7513`,
`auth.token`, no unknown key). Every row was run through a bounded runner;
**rc 124 means the process started successfully and was killed by the bound**,
which is how the lenient server rows are recorded. Rows marked *(warns)* print
the stderr line above; every other row is silent.

| argv | Go v0.71.0 | frp-rs |
|---|---|---|
| `frpc reload -c bad.toml` (absent) | rc 1, `json: unknown field "notAKnownFrpKey"` | rc 1, `unknown field "notAKnownFrpKey" in config file …` |
| `frpc reload --strict-config -c bad.toml` (bare) | rc 1, same | rc 1, same |
| `frpc reload --strict_config -c bad.toml` (bare, `_`) | rc 1, same | rc 1, same |
| `frpc reload --strict-config=true -c bad.toml` | rc 1, same | rc 1, same |
| `frpc reload --strict-config=false -c bad.toml` | rc 1, dials `127.0.0.1:7499` | rc 1, dials `127.0.0.1:7499` |
| `frpc reload --strict-config false -c bad.toml` *(warns)* | rc 1, `json: unknown field …`, **no dial** (`false` is a positional) | rc 1, dials `7499` — **extension** |
| `frpc reload --strict-config foo -c bad.toml` | rc 1, `json: unknown field …`; the stray token is ignored and strict stays `true` | rc 1, ``Error: `foo` is not expected in this context`` |
| `frpc reload --strict-config=foo -c bad.toml` | rc 1, `Error: invalid argument "foo" for "--strict-config" flag: strconv.ParseBool: parsing "foo": invalid syntax` | rc 1, ``Error: `foo` is not expected in this context`` |
| `frpc --strict-config false -c bad.toml` (run) *(warns)* | rc 1, `Error: unknown command "false" for "frpc"` (the root command takes no positional) | rc 1, lenient: connects to `127.0.0.1:7500` |
| `frpc --strict-config=false -c bad.toml` (run) | rc 1, lenient: connects to `7500` | rc 1, lenient: connects to `7500` |
| `frpc verify --strict-config false -c bad.toml` *(warns)* | rc 1, `json: unknown field …` | **rc 0**, Go's `frpc: the configuration file … syntax is ok` first line (plus the three summary lines) — **extension** |
| `frpc verify -c bad.toml --strict-config false` *(warns)* | rc 1, `json: unknown field …` — position changes nothing | **rc 0**, the same Go first line — **extension** |
| `frpc verify --strict-config=false -c bad.toml` | rc 0, `syntax is ok` | rc 0, the same Go first line |
| `frpc status \| stop --strict-config false -c bad.toml` *(warns)* | rc 1, `json: unknown field …`, no dial | rc 1, dials `7499` — **extension** |
| `frpc verify --strict-config "" -c bad.toml` | rc 1, `json: unknown field …` — the empty token is a positional | rc 1, ``Error: `` is not expected in this context`` |
| `frpc verify --strict-config "" -c good.toml` | **rc 0**, `syntax is ok` — positional ignored, config valid | rc 1, ``Error: `` is not expected in this context`` |
| `frpc verify --strict-config= -c bad.toml` | rc 1, `invalid argument "" for "--strict-config" flag: strconv.ParseBool: parsing "": invalid syntax` | rc 1, ``Error: `` is not expected in this context`` |
| `frpc verify --strict-config=true --strict-config=false -c bad.toml` (repeated) | **rc 0**, `syntax is ok` — pflag is last-wins, so lenient | rc 1, ``argument `--strict-config` cannot be used multiple times in this context`` |
| `frpc verify --strict-config=false --strict-config=true -c bad.toml` (repeated) | rc 1, `json: unknown field …` — last-wins, so strict | rc 1, the same repetition refusal |
| `frps --strict-config=false -c badfrps2.toml` | rc 124 — starts (lenient) | rc 124 — starts (lenient) |
| `frps --strict-config false -c badfrps2.toml` *(warns)* | rc 1, `Error: unknown command "false" for "frps"` | rc 124 — starts (lenient) — **extension** |
| `frps verify --strict-config false -c badfrps2.toml` *(warns)* | rc 1, `json: unknown field …` — the token is an ignored positional and strict stays `true` | **rc 0**, `frps: the configuration file … syntax is ok` — the value is read and strict is off — **extension**, the same one `frpc verify --strict-config false` carries. It also warns on stderr |
| `frps verify --strict-config=true -c badfrps2.toml` | rc 1, `json: unknown field …` | rc 1, `unknown field … in config file <path>` — the `=` form is Go-faithful |
| `frps verify --strict-config=false -c badfrps2.toml` | rc 0, `frps: the configuration file badfrps2.toml syntax is ok` | rc 0, the same line at this head; the client's `frpc verify` also starts with Go's sentence now and follows it with its three summary lines (§ Output stream and shape on a config-load failure) |
| `frps verify --strict-config foo -c goodfrps.toml` | **rc 0**, `syntax is ok` — the stray token is an ignored positional and strict stays `true` | rc 1, ``Error: `foo` is not expected in this context`` — the pre-existing positional divergence, the same one `frpc verify --strict-config foo -c good.toml` has (measured: Go rc 0, frp-rs rc 1) |
| `frps --strict-config foo -c badfrps2.toml` | rc 1, `Error: unknown command "foo" for "frps"` | rc 1, ``Error: `foo` is not expected in this context`` |
| `frps --strict-config=foo -c badfrps2.toml` | rc 1, `invalid argument "foo" … strconv.ParseBool` | rc 1, ``Error: `foo` is not expected in this context`` |

What the table says, precisely:

- **The `=` form is Go-faithful on every parser for a single occurrence** —
  `frps`'s run path, `frps verify`, and `frpc`'s `run`/`verify`/`reload`/
  `status`/`stop` (seven parsers; `frps verify` is the one this round added, and
  it is the same `strict_config_parser` inside `svr_meta`) — for `=true`,
  `=false`, and a bad `=foo` (both exit 1; only the message differs). A
  **repeated** flag is *not* Go-faithful and is not covered by that sentence:
  Go's pflag is last-wins (`=true =false` → rc 0 lenient, the reverse → rc 1
  strict) while frp-rs refuses the repetition outright with rc 1 in both orders.
  The rc agrees on one of those orders and not on the other; the reason differs
  on both.
- **The space form is the only divergence in flag *values*.** frp-rs consumes
  the next token as the value, which is why the lenient rows above dial where
  Go refuses. On the two *root* commands (`frpc`, `frps`) Go answers
  `unknown command "false"` instead — it takes no positional — while the `frpc`
  subcommands and `frps verify` accept the argv and silently ignore the token,
  keeping strict on. **Position does not matter**: with `-c` first the same
  divergence reproduces on both binaries (measured above), so the warning is tied
  to the flag, not to where it sits in the argv.
- **Only a bool value is consumed — the empty token is not.** `--strict-config
  ""` is an argv error on frp-rs (bpaf takes no empty value), and on Go the empty
  token is an ignored positional, so with a valid config Go exits **0** where
  frp-rs exits 1. That is a second, pre-existing "frp-rs stricter than Go"
  divergence on the same flag, in the opposite direction from the extension; it
  is recorded here rather than fixed. The attached `--strict-config=` fails on
  both (Go: pflag's `ParseBool`; frp-rs: the same leftover-token message as
  `--strict-config foo`), and neither warns.
- **`--strict-config foo` is a different divergence from `--strict-config=foo`.**
  Go ignores the stray space-separated token (the config is still loaded, rc 1
  only because the config itself is refused) where frp-rs refuses the argv
  outright; Go's `=foo` is pflag's own `strconv.ParseBool` error. All three exit
  1, and frp-rs's message is the same for both spellings.
- **`frps` is covered, not out of scope.** Go's server registers the same pflag
  bool (its `--help` carries Go's text `strict config parsing mode, unknown
  fields will cause errors (default true)`), so the extension applies there too,
  is stated in the same help text, and warns from the same detection.
- **"The `=` spelling is Go-faithful" started as a per-flag rule and is now a
  CLI-wide one for bool flags.** When this item landed it held only for
  `--strict-config`, because that flag went through the shared bool-value
  parser, and it did **not** hold for flags still on a plain `.switch()`:
  measured then on `frps` with the valid server config (`goodfrps.toml`, bounded
  runner), four flags accepted the pflag `=value` spelling on Go (rc 124 — it
  starts and listens) and were refused by frp-rs with rc 1
  (``Error: `false` is not expected in this context``): `--tls-only=false`,
  `--enable-prometheus=false`, `--disable-log-color=false` and
  `--dashboard-tls-mode=false`. That list was **representative, not exhaustive**
  — four probed, no sweep — and the class was "any bool flag registered as a
  bpaf `switch()` on either binary". It is now closed by the sweep below, which
  routes all ten such flags through the same parser
  ([§ `--flag=<bool>`](#--flagbool-the-pflag-value-spelling-on-both-binaries)).
  The Go bool flags frp-rs does **not** register (`frpc tcp --ue`/`--uc`, whose
  long spellings here are `--use-encryption`/`--use-compression`, and
  `--tls-enable`) are part of the same direction and are recorded there instead
  of being silently matched: `--use-encryption` itself has no Go behaviour to
  match (`Error: unknown flag: --use-encryption`, rc 1), so only its *value
  grammar* follows Go.

Why the extension is kept, as the measured trade the done-when asks for:

- **Keeping preserves argv acceptance and every existing invocation.** The
  measured cost is a *silent* behaviour difference for a Go-written argv: `frpc
  verify --strict-config false -c good.toml` is rc 0 on **both** binaries today
  (Go: strict but the config is valid; frp-rs: lenient), and
  `frpc reload --strict-config false -c host.toml` is rc 1 on both (Go's request
  carries `?strictConfig=true`, frp-rs dials the same address). What differs is
  *which load happened*, which is why the warning — not just the docs — is the
  mitigation.
- **Dropping (bpaf `ParseArgument::adjacent()`, one method call) makes that
  divergence loud but converts a Go-succeeding argv into an frp-rs failure.**
  Measured with the drop branch built:
  `frpc verify --strict-config false -c good.toml` → Go **rc 0**
  (`syntax is ok`), drop branch **rc 1** (``Error: `false` is not expected in
  this context``) — *this* is the load-bearing row, because the config is valid
  and the argv succeeds on Go; `frpc verify --strict-config false -c bad.toml` →
  Go rc 1, drop rc 1 (rc agrees, reason does not); `frpc reload --strict-config
  false -c host.toml` → Go rc 1, drop rc 1. On the **root** command the same
  argv is a failure on both sides already: `frps --strict-config false -c
  goodfrps.toml` → Go **rc 1** (`Error: unknown command "false" for "frps"` — it
  takes no positional and refuses before reading the config), head rc 124 (the
  extension starts), drop rc 1, so there Go and the drop branch *agree* on the
  code and that row is completeness rather than evidence. The `=` spellings keep
  working under the drop branch (`frps --strict-config=false` still starts). So
  the drop branch improves raw rc agreement on the config-refusal rows by turning
  *behaviour* differences into *acceptance* differences — it refuses argv that Go
  accepts and simply ignores the token on. This document does not quote a global
  mismatch count; the reviewers' matrices are theirs, and the rows above are the
  ones measured here.
- **The decision is keep + warn.** The space form honours the user's obvious
  intent, existing invocations keep working, and the silent part of the
  divergence — the part that made this item worth filing — is now printed on
  stderr by every parser that can consume it, with the Go-faithful spelling in
  the same line. The repo already keeps bounded, documented extensions
  (`--config-dir`, `--admin-addr`, the V1 type bytes 7/8); this one announces
  itself on every use.
- **The blast radius of changing it is small, but non-zero.** A tree-wide
  `git grep` for the two-token form finds no script and no other doc — only the
  unit tests and this item — so nothing *documents* a dependency on the form;
  changing it would still alter behaviour for any user who typed it.

Carriers, all of which agree:

- the **warning**: `STRICT_CONFIG_SPACE_FORM_WARNING` (`frp-core/src/cli.rs`),
  printed from `parse_frps_args`/`parse_frpc_args` after a successful parse and
  gated by `strict_config_space_form_used`, which mirrors bpaf's consumption rule
  (a `--strict-config`/`--strict_config` token immediately followed by a
  non-`-`-prefixed bool). Pinned by `strict_config_warning_text_is_the_documented_line`
  (exact text), `strict_config_warning_detection_matches_the_consumed_shape`
  (the shapes that must and must not be detected, including the bare switch and
  `--strict-config --config x`), `space_form_warning_fires_on_each_frpc_parser`
  (real binary, one row per `frpc` parser, plus the silent `=` rows) and
  `space_form_strict_config_warns_on_stderr` (`frps/tests/cli_exit_codes.rs`);
- the **help text** of every parser that takes the flag, from one definition
  (`strict_config_parser` in `frp-core/src/cli.rs`) — the bare-form line names
  the Go-faithful spellings, states that frp-rs additionally consumes a
  space-separated value "which Go's pflag does not", and says a warning is
  printed; the `=BOOL` line names the Go-faithful value spelling. Pinned by
  `strict_config_help_text_states_the_extension` (`frp-core/src/cli.rs`), which
  asserts **each entry separately** — the rendered `--help` of all six parsers
  must contain the squashed help const *and* the const must still carry its
  meaning (independent literals), so neither a deleted value-form `.help()` nor
  an inverted bare-form help passes;
- `CHANGELOG.md` (Unreleased § Changed, for the warning, and § Docs) and this
  section;
- the parser tests `strict_config_defaults_to_true`,
  `strict_config_bare_flag_is_true`, `strict_config_equals_true_parses`,
  `strict_config_equals_false_parses_and_disables`,
  `strict_config_space_separated_value_parses` and
  `strict_config_invalid_value_errors_cleanly` (`frp-core/src/cli.rs`), each run
  across all six parsers (their `.unwrap()`s carry the parser label, so a
  failure names which parser broke);
- the real-binary pins `verify_strict_config_spellings_match_their_measured_rows`
  (`frpc/tests/cli_inputs.rs`: rc, which load happened, the warning for every
  spelling, both repeated-flag orders, both empty-value spellings and the
  position row) and `reload_space_separated_strict_config_is_consumed_as_the_value`
  / `reload_bare_strict_config_stays_strict_and_never_connects`
  (`frpc/tests/admin_cli.rs`, the mock-admin connection as proof of the consumed
  value and its strict-mode control).

#### `--flag=<bool>`: the pflag value spelling on both binaries

Five of these ten flags are a pflag bool **under the same name on the same Go
command**: `frps --tls-only`, `--enable-prometheus`, `--disable-log-color`,
`-v`/`--version` and `frpc -v`/`--version`. Two more are Go pflag bools under a
different name (`frpc tcp --use-encryption`/`--use-compression` are Go's `--ue`/
`--uc`, on all eight proxy subcommands). One is a Go pflag bool on a *different*
command (`frpc --disable-log-color` is on those eight, not on the root). One is
a **string** flag on Go (`--dashboard-tls-mode`). One has no Go flag at all
(`frpc status --json`).

For every one of them that Go registers as a pflag bool, Go accepts three
spellings of **one** flag: the bare `--flag` (sets `true`), `--flag=true` and
`--flag=false`. The attached value is parsed by `strconv.ParseBool`, so `1`,
`0`, `t`, `f`, `T`, `F`, `TRUE`, `FALSE`, `True` and `False` are accepted and
anything else is `Error: invalid argument "foo" for "--flag" flag:
strconv.ParseBool: parsing "foo": invalid syntax` (rc 1). A pflag bool never
consumes a following token, so `--flag <bool>` is not a value there — and a bool
**short** never takes an attached value either: `-vtrue` sets `-v` and re-parses
the rest as more shorthands, while only `-v=<bool>` is a value.

frp-rs registered the ten as bpaf `.switch()`es, which implement only the bare
form, so argv Go accepts exited 1 here with `` `false` is not expected in this
context `` (`TODO.md:3498`). They now all go through one macro,
`go_bool_flag!` (`frp-core/src/cli.rs`): a `parse_go_bool` value branch marked
`.adjacent()` — only `--flag=<value>` is a value — plus the bare
`.flag(true, false)` fallback, so present → `true` and absent → `false`, exactly
the `.switch()` it replaces. The space-separated form is deliberately **not**
consumed: `.adjacent()` keeps this byte-identical to the pre-change refusal
instead of adding a second extension like `--strict-config`'s.

**The value branch is long-only, and that is not cosmetic.** A **short** in an
`.adjacent()` argument breaks bpaf's branch selection: `ParseArgument` pushes the
named argument onto `State::path` as soon as it *attempts* a token
(`bpaf-0.9.27/src/params.rs:451`), so the value branch is reported one level
deeper than the flag branch and `this_or_that_picks_first`
(`bpaf-0.9.27/src/structs.rs:322-350`) returns the deeper branch's error even
when the flag branch parsed the token successfully. Measured with the short in
both branches: `frps -vtrue`, `-vh`, `-vtok`, `-vp7000` — pflag shorthand
clusters that set `-v` and re-parse the rest, rc 0 on Go **and rc 0 at the base
head** — all became rc 1 with `` `-vtrue` is not expected in this context ``.
Branch order does not fix it (switching the two made `-v` alone stop setting the
flag at all), so the short goes to the flag branch only and pflag's `-v=<bool>`
spelling — the same variable as `--version=<bool>` there — is expanded to
`--version=<bool>` before bpaf sees argv
(`expand_bool_short_value_form`). That is the only bool short either binary
registers; every other short (`-c`, `-t`, `-p`, `-L`, …) takes a value and
already parses its `=` spelling. The rewrite also stops at the first `--`:
nothing after it is a flag, and rewriting there would put a token the user never
typed into a rejection message (`frps -- -v=false` must answer
`` `-v=false` is not expected ``, as the base head and Go do, not
`` `--version=false` ``).

The two entry points therefore build bpaf's `Args` by hand (`cli_args` /
`run_cli`) so the rewrite has a place to live, and they reproduce
`OptionParser::run`'s own behaviour exactly: `print_message(100)` (bpaf's
default `max_width`) then `exit_code()`, `argv[0]` dropped the way
`Args::current_args` drops it, and `set_name` called **only** when argv[0] yields
a UTF-8 file name — never a hardcoded program name, which would make `frpc`
render `Usage: frps …` for an argv[0] bpaf cannot read. Help and error output
were diffed byte-for-byte against the previous build over 14 argvs (help on five
surfaces, nine parse-error paths) **and** over argv[0] shapes
(`b"frpc"`, `b"frpc\xff"`, `b""`, `b"weird/name.bin"`): the only differences are
the intended usage-line spelling (`(--version=BOOL | [-v])` instead of
`(-v=BOOL | [-v])`), the two new help entries, and the nameless usage line
`Args::current_args` also produces for an unreadable argv[0].

The sweep — every bpaf `.switch()` on either binary. At the base commit
`grep -n "\.switch()" frp-core/src/cli.rs` returned those ten sites (plus the
one match inside a doc comment); all ten are now on the shared parser, and the
list below is what the sweep found:

| flag | frp-rs surface | Go's flag of that name |
|---|---|---|
| `--tls-only` | `frps` | pflag bool |
| `--enable-prometheus` | `frps` | pflag bool |
| `--disable-log-color` | `frps` | pflag bool |
| `--dashboard-tls-mode` | `frps` | **string** flag, not a bool |
| `-v`, `--version` | `frps` | pflag bool |
| `--disable-log-color` | `frpc` (run) | **not on the root** — on the eight proxy subcommands |
| `-v`, `--version` | `frpc` (run) | pflag bool (persistent rootCmd flag) |
| `--use-encryption` | `frpc tcp` | Go spells it `--ue` |
| `--use-compression` | `frpc tcp` | Go spells it `--uc` |
| `--json` | `frpc status` | **no Go flag at all** |

One row of this sweep moved afterwards: `TODO.md:4506` registered the five
persistent rootCmd flags — `-c`, `--config-dir`, `--strict-config`,
`--allow-unsafe` and `-v`/`--version` — on all twelve `frpc` subcommands as
accepted-and-ignored parsers, so `-v`/`--version` is no longer run-mode-only on
`frpc` ([§ The persistent rootCmd flags on every
subcommand](#the-persistent-rootcmd-flags-on-every-subcommand)). The other nine
rows are unchanged.

Measured 2026-09-26 on Go frp **v0.71.0** (darwin/arm64,
`/private/tmp/frp_0.71.0_darwin_arm64/`) against the frp-rs binaries built from
the base commit (`2b1d51f`) and from this branch's head. Server configs are
generated per row with a fresh free `bindPort` and `auth.token`; the `frpc` rows
either point at a standing Go `frps` or carry `frpc tcp`'s own required flags
(`--local-port`/`--remote-port`/`--proxy-name`/`--server-port`), because at that
head frp-rs's `tcp` subcommand had no `-c` at all (it accepts and ignores it
since `TODO.md:4506`). Every child was bounded and killed
on the bound: **rc 124 = the process started and was killed**, which is how
"Go starts and listens" is recorded. Rows are `Go / frp-rs before / frp-rs
after`.

Server-side (`frps`, valid config):

| argv | Go | before | after |
|---|---|---|---|
| `--tls-only` (bare) | 124 | 124 | 124 |
| `--tls-only=true` | 124 | 1 | **124** |
| `--tls-only=false` | 124 | 1 | **124** |
| `--tls-only=1` / `=0` | 124 / 124 | 1 / 1 | **124 / 124** |
| `--tls-only=foo` | 1 | 1 | 1 |
| `--tls-only false` (space) | 1 `unknown command "false"` | 1 | 1 |
| `--enable-prometheus` / `--disable-log-color`, all four bool spellings | 124 | 1 | **124** |
| `--dashboard-tls-mode=true` / `=false` / `=1` / `=0` | 124 | 1 | **124** |
| `--dashboard-tls-mode=auto` / `=disable` / `=` (empty) / `=foo` | **124** | 1 | 1 — Go's flag is a **string** |
| `--dashboard-tls-mode` (bare) | **1** `unknown command "<cfg>"` — it consumes `-c`, which then dangles | 124 | 124 |
| `--version` (bare) / `=true` / `=1` | 0, version on stdout | 0 (bare) / 1 | 0 |
| `--version=false` / `=0` | 124 | 1 | **124** |
| `--version=foo` | 1 `strconv.ParseBool` | 1 | 1 |
| `-v=false` (short + `=`) | 124 | 1 | **124** |
| `-vtrue` / `-vtok` / `-vp7000` *(short cluster)* | 0, version on stdout | 0 | **0** |
| `-vh` *(short cluster)* | 0, help on stdout | 0 | **0** |
| `-vfoo` / `-v0` *(unknown short)* | 1 `unknown shorthand flag: 'f' in -foo` / `… '0' in -0` | 1 | 1 (`` `-vfoo` is not expected in this context ``) |
| `--tls-only --tls-only=false` *(repeated)* | 124 — pflag is last-wins | 1 | 1 |

Client-side (`frpc`; the `frpc tcp` pair is compared against its Go names):

| argv | Go | before | after |
|---|---|---|---|
| `frpc --version` (bare) / `=true` / `=1` | 0, version on stdout | 0 | 0 |
| `frpc --version=false` / `=0` | 124 (client starts) | **0, version** | **124** |
| `frpc --version=foo` | 1 `strconv.ParseBool` | **0, version** | **1** |
| `frpc --nope=1 --version` | 1 `unknown flag: --nope` | **0, version** | **1** |
| `frpc -v=false` | 124 | 0, version | **124** |
| `frpc -vtrue` *(short cluster)* | 1 `unknown shorthand flag: 't' in -true` (`-t` is not a run-mode flag there) | 0, version | 1 |
| `frpc -vc<path>` / `frpc -vh` *(short cluster)* | 0, version / 0, help | 0, version / 0, version | **0** / **0, help** |
| `frpc -vLdebug` *(short cluster)* | 1 `unknown shorthand flag: 'L' in -Ldebug` | 0, version | 0, version — pre-existing: `-L` is an frp-rs-only short |
| `frpc --disable-log-color=false -c <cfg>` | 1 `unknown flag` (no such flag on Go's root) | 1 | 124 — the flag itself is a pre-existing placement divergence |
| `frpc tcp --ue=false …` / `--use-encryption=false …` | 124 | 1 | **124** |
| `frpc tcp --ue=foo …` / `--use-encryption=foo …` | 1 | 1 | 1 |
| `frpc tcp --ue false …` / `--use-encryption false …` *(space)* | **124** — accepted, the token is not a value (a pflag bool never consumes one; the same machinery is why `frps --tls-only false` leaves the token and answers `unknown command`) | 1 | 1 |
| `frpc status --json` / `=true` / `=false` | 1 `unknown flag: --json` | 1 | 1 (the value is consumed; `status` then reports the missing admin port) |

What the table says, precisely:

- **The `=BOOL` spelling is Go-faithful for the eight flags Go registers as
  pflag bools** — five by the same name, `frpc tcp`'s pair by Go's `--ue`/
  `--uc`, and `frpc --disable-log-color` on the command Go registers it on — for
  every value `strconv.ParseBool` accepts and for a bad value (both exit 1; only
  the message differs). One of the remaining two is `--dashboard-tls-mode`: Go's
  flag is a
  **string**, so it also accepts `=auto`, `=bogus`, the empty value, and its
  bare form swallows the next token (`frps --dashboard-tls-mode -c cfg` is
  `unknown command "cfg"`, rc 1, while frp-rs treats the bare form as `true` and
  starts). frp-rs models the field as a bool, so only the bool-shaped values —
  which Go happens to accept as strings — can be honoured; the residue is a
  **modelling** divergence, not a value-spelling one, and it is unchanged by
  this work. The value spelling is still an improvement (four rows move from 1
  to 124), but it is *not* parity for that flag.
- **The space-separated form is refused, and Go is not uniform about it.** The
  refusal (`Error: `false` is not expected in this context`, rc 1) is unchanged
  from the pre-change switch, and it agrees with Go exactly where Go's command
  takes no positional argument: the two root commands (`frps`, `frpc`) answer
  `Error: unknown command "false" for "frps"`, also rc 1. It does **not** agree
  where Go ignores or consumes the token: `frpc tcp --ue false …` is accepted
  there and starts (rc 124) — the token is not a value for a pflag bool, and the
  `frps --tls-only false` row above shows the same machinery *not* consuming it —
  while `--dashboard-tls-mode false` is consumed as that string flag's value.
  Those
  rows stay rc 1 here and are recorded rather than matched, because matching
  them would mean *consuming* a token Go's bool never consumes — the same
  divergence `--strict-config` documents, without that flag's ability to warn
  (there is no single "the value was consumed" point to key on when the token is
  a stray positional in some commands and a value in others).
- **A repeated flag is refused, not last-wins.** Go's pflag is last-wins
  (`frps --tls-only --tls-only=false` → 124, the reverse order → 124 too), while
  every one of these flags fails the second occurrence with rc 1
  (``argument `--tls-only` cannot be used multiple times in this context`` /
  ``… cannot be used at the same time as `--tls-only` ``). This is a
  pre-existing, recorded divergence of the shared parser shape, the same one
  `--strict-config` has; it is pinned by
  `every_go_bool_flag_rejects_a_repeated_flag` so it cannot drift silently.
- **`--json` has no Go counterpart.** `frpc status --json` is an frp-rs-only
  flag (`Error: unknown flag: --json`, rc 1, for every spelling on Go), so its
  `=BOOL` value spelling is an frp-rs extension of the shared parser; the flag's
  own help says so, and the meaning and the value form are the only things Go
  cannot confirm.
- **`--disable-log-color` is on a different `frpc` command than on Go.** Go
  registers it on its **eight single-proxy subcommands** — `tcp`, `udp`, `http`,
  `https`, `stcp`, `xtcp`, `sudp`, `tcpmux`, and their `visitor` forms for the
  last three (measured: `frpc <cmd> --help` lists it on all eight; not on the
  root) — so `frpc --disable-log-color=false -c cfg` starts here (124) and is
  `unknown flag` there (1); the bare form already diverged the same way. That is
  a **flag-placement** divergence, recorded and not addressed here.
- **Four Go bools are not implemented at all**, and they are not `frpc tcp`'s
  alone: `--ue`, `--uc` (the short spellings of the pair frp-rs calls
  `--use-encryption`/`--use-compression`), `--tls-enable` (Go's default-true
  client-TLS switch) and `--disable-log-color`. Measured with
  `frpc <cmd> --help`: all four are on **all eight** single-proxy subcommands,
  and on `stcp|xtcp|sudp visitor` too; `frpc completion <shell>` also carries
  cobra's `--no-descriptions`. Go accepts them with the usual bool grammar
  (`--tls-enable=false …` → 124; `--tls-enable=foo` → 1), frp-rs refuses the name
  (`` `--tls-enable` is not expected in this context ``, rc 1; `--disable-log-color`
  is accepted on the client **root** instead — the placement row above). They are
  a surface gap, not a spelling gap.
- **`--version` on `frpc` was two defects, and both needed the same fix.** The
  flag was a `.switch()` (so `--version=false` was an argv error where Go starts
  the client), and the version check lived in a `.map()` closure on
  `frpc_parser()`'s run branch. bpaf's `ParseOrElse` evaluates **every**
  alternative on a forked state, so that closure printed the version and called
  `process::exit(0)` while bpaf was still choosing a branch: at the base commit
  `frpc --version=foo` and even `frpc --nope=1 --version` printed
  `frpc 0.71.0 (Rust)` and exited **0** where Go exits 1. The check now runs in
  `parse_frpc_args` after `run()` returns, exactly as `parse_frps_args` already
  did, which fixes the non-bool values (rc 1) and the invalid-flag row (rc 1)
  and keeps `--version` → 0.
- **`--version` is a persistent flag on Go; it was only a run-mode flag here
  until `TODO.md:4506` registered the persistent set.** Moving the version check
  out of the parser changed four subcommand rows, measured Go / base head / the
  head of that branch: `frpc verify --version -c <valid>` is rc **0** on Go (the
  persistent bool parses and `verify` ignores it, then runs) and was rc 0 here
  before — printing the version instead of verifying — but became rc **1**
  there; `frpc verify --version` with **no** `-c` is rc 1 on Go too (it falls
  back to `./frpc.ini`), and rc 1 here for the other reason. `frpc tcp --version
  --local-port … --remote-port …`: Go starts the proxy and ignores the
  persistent flag (rc 124 under a `timeout` probe), the base head printed the
  version (rc 0), that head rc 1. The regression is repaired now: the five
  persistent rootCmd flags are registered on all twelve `frpc` subcommand
  parsers and dropped, so `frpc verify --version -c <valid>` is rc 0 again,
  `frpc tcp … --version` starts the proxy, and
  `frpc reload|status|stop --version -c <valid>` parse the flag and dial the
  admin API — all matching Go. The same registration covers the other four
  persistent flags, measured with an `<unknown-key config>` so the rc 1 on Go is
  the *config* refusal and proves the flag parsed: `frpc verify
  --allow-unsafe=TokenSourceExec -c …` and `frpc verify --config-dir=… -c …` are
  rc 1 `json: unknown field "notAKnownFrpKey"` on Go and rc 1 with the same
  unknown-field error here (both load the file now). Scope, table and residual
  divergences: [§ The persistent rootCmd flags on every
  subcommand](#the-persistent-rootcmd-flags-on-every-subcommand).
- **A rejection message can name the expanded spelling.** Because `-v=<bool>`
  becomes `--version=<bool>` before bpaf parses, a *refused* token is reported
  under its long name: at the head where the persistent flags were still
  unregistered, measured, `frpc status -v=false -c <cfg>` was rc 1
  `` `--version` is not expected in this context ``, where the base head printed
  the version and exited **0** (the speculative-`exit` defect this branch fixes;
  it emitted no diagnostic at all) and the first-revision head said `` `-v` ``
  (rc 1 — the token there is the short `-v`, not `-v=false`). Go is rc 1 there
  too (the persistent flag parses, `status` ignores it and dials the admin API).
  The `--` guard keeps the rewrite honest where it would be gratuitous
  (`frps -- -v=false` names `-v=false`, byte-identical to the base head). After
  `TODO.md:4506` there is no `frpc` row left that refuses a `-v=<bool>`
  spelling — `frpc status -v=false -c <cfg>` dials the admin API as Go does — so
  the remaining alias-in-message case is on `frps`, a separate surface. Related
  and unchanged for `frps`: Go *accepts* `frps -p <free> -- xyz` (it starts, rc
  124) while frp-rs refuses the stray positional (rc 1, `` `xyz` is not
  expected ``) — the same stricter-than-Go-positional class as the space form
  above, no `-v` involved. (Go ignores positional args on `frpc` too; that half
  is recorded in [§ The persistent rootCmd flags on every
  subcommand](#the-persistent-rootcmd-flags-on-every-subcommand).)
- **The help *shape* is user-visible and different from Go's.** frp-rs renders
  **two** entries per bool flag — `--flag=BOOL` (the value spelling) and
  `--flag` (the bare form) — and a usage alternation
  `(--version=BOOL | [-v])`, where Go prints a single `-v, --version  version of
  frps` line and no separate value entry. That rendering is pinned by
  `every_go_bool_flag_help_states_its_own_spelling` (spaces removed before the
  assertion, because the usage line wraps at the output width). The `-v=<bool>` spelling works but is
  not advertised as its own entry (it is expanded to `--version=<bool>` at the
  entry point). That is a deliberate consequence of having one parser for both
  spellings, recorded rather than described as parity; nothing in Go's help
  string is contradicted, the same information is just laid out differently.
- **`--help`/`-h` is a pflag bool on Go too, and is not covered by this
  parser.** It is not one of the ten `.switch()` sites: bpaf owns `--help` as
  `Info::help_arg`, so it has its own two pre-parse passes instead of the
  `go_bool_flag!` macro, and the two entry points own the ordering — see
  [§ `--help=<bool>`: the bool that a subcommand can follow](#--helpbool-the-bool-that-a-subcommand-can-follow).
  The **root** half is still divergent and deliberately so:
  `frps --help=false -c cfg` starts the server there (124) and prints help here
  (0, bpaf's built-in help parser, which accepts the attached value and ignores
  it) — the pass leaves the token in place when no command word follows it.
  The **subcommand** half (`--help=false status`, `--help=true status`, `-hc`)
  is fixed there, with its measurements.

Carriers, all of which agree:

- the **parser**: `go_bool_flag!` and its two documented variants
  (`go_bool_flag_go_string!` for `--dashboard-tls-mode`,
  `go_bool_flag_rs_only!` for `--json`) in `frp-core/src/cli.rs`, so the help
  text's claim about Go is derived from which macro the call site uses and the
  flag name in the help is the name the parser registers (`concat!`, not a
  second literal);
- the **entry points**: `expand_bool_short_value_form` plus `cli_args`/`run_cli`
  (`frp-core/src/cli.rs`), which expand pflag's `-v=<bool>` short spelling (never
  past a `--`) and hand bpaf the same `Args` (`set_name` only when argv[0] yields
  a name, `print_message(100)`, `exit_code()`) that `OptionParser::run` would
  have built; pinned at unit level by
  `bool_short_equals_spelling_expands_to_the_long_form_only`;
- the **help text**, one `=BOOL` entry and one bare entry per flag, rendered by
  `--help` on all four surfaces (`frps`, `frpc` run, `frpc tcp`,
  `frpc status`);
- `CHANGELOG.md` (Unreleased § Features for the newly accepted spellings, § Fixed
  for the `frpc --version` short-circuit) and this section;
- the parser tests `every_go_bool_flag_accepts_the_pflag_value_spellings`,
  `every_go_bool_flag_refuses_non_bool_values_and_the_space_form`,
  `every_go_bool_flag_help_states_its_own_spelling` and
  `every_go_bool_flag_rejects_a_repeated_flag` (`frp-core/src/cli.rs`), which
  read their flag list from one `GO_BOOL_SITES` table so a site cannot be
  dropped from the sweep without the count moving;
- the real-binary pins `version_flag_value_spelling_decides_what_happens`,
  `version_short_shorthand_clusters_and_equals_spelling_match_go`,
  `tls_only_false_value_starts_and_listens` and
  `disable_log_color_value_spelling_is_applied` (`frps/tests/cli_exit_codes.rs`)
  and `version_flag_value_spelling_decides_what_happens` /
  `disable_log_color_value_spelling_is_consumed`
  (`frpc/tests/cli_exit_codes.rs`), which assert the rc **and** what happened
  (version or help on stdout, the missing config named, a real listener
  accepting a connection, and — for the value actually being applied — ANSI
  escapes present with `=false` and absent with `=true`). The `tls_only` test's
  own doc comment states what it does *not* prove: with `-c` present the
  config's transport section is authoritative (`cli_overrides_enabled()`), so it
  pins argv acceptance, not that `false` reached the service.

#### `--help=<bool>`: the bool that a subcommand can follow

`--help`/`-h` is one of the pflag bools above, but it is registered by **cobra**
(`InitDefaultHelpFlag`, `cobra-1.8.0/command.go:1186`) inside `execute` — after
`Find` has already run `stripFlags` — so it is the one bool that is *not* in
`RootCommand::bool_root_flags` and *does* consume the next token during command
resolution (`frpc --help status` prints the **root** help on Go, not `status`'s).
On the parse side it behaves like every other pflag bool: `--help=false` sets it
to `false` and cobra then runs the command normally
(`cobra-1.8.0/command.go:892-894`), while `--help=true` prints the resolved
command's own help.

bpaf has no such flag to parse. `--help` is `Info::help_arg`
(`bpaf-0.9.27/src/info.rs:41`), which the inner parser never sees: bpaf evaluates
it only after parsing fails, and a value attached with `=` makes the parse fail,
so `--help=false status` used to short-circuit to help. Measured on Go frp
v0.71.0 darwin/arm64 against the base head (`5b18489`) and this head, stdout and
stderr captured separately, rc read from the child directly, and **one fresh
listening socket per run** on the config's `[webServer] port` with connections
counted by `accept`:

| argv | Go v0.71.0 | frp-rs base | frp-rs head |
|---|---|---|---|
| `--help=false status -c CFG` (port set) | rc 1, **1 connection** (it dialled), stdout 45 B, stderr 0 B | rc 0, **0 connections**, `status`'s bpaf usage 1604 B on stdout | rc 1, **1 connection**, stdout 0 B, stderr 22 B (`status query failed: `) |
| the same with no `port` | rc 1, 0 connections, stdout 62 B `web server port should be set if you want to use this feature` | rc 0, 0 connections, the same 1604 B usage | rc 1, 0 connections, the same 62 B line |
| `--help=true status -c CFG` | rc 0, 0 connections, stdout 627 B (`Overview of all proxies status` + `Usage: frpc status [flags]`) | rc 0, 0 connections, 1604 B of bpaf usage | rc 0, 0 connections, 1604 B of bpaf usage |
| `-hc status` | rc 1, **stderr** 637 B `Error: flag needs an argument: 'c' in -c` + usage, stdout 0 B | rc 0, usage 1604 B on **stdout** | rc 1, **stderr** 41 B, the same first line, stdout 0 B |
| `-hc` | rc 1, stderr 1351 B, stdout 0 B | rc 0, root usage 2405 B on stdout | rc 1, stderr 41 B, stdout 0 B |
| `-h -c status` | rc 1, stderr 637 B, stdout 0 B | rc 0, 1604 B on stdout | **rc 1, stderr 41 B, stdout 0 B** (pflag's `flag needs an argument: 'c' in -c`; the split `-h` family is fixed, minus cobra's usage block) |
| `-hc status -c CFG` | rc 0, `status`'s help | rc 0, bpaf usage | rc 0, bpaf usage (unchanged) |
| `--help=foo status` | rc 1, stderr 698 B, stdout 0 B | rc 0, usage 1604 B on stdout | rc 1, stderr 102 B, stdout 0 B |
| `--help=` (empty) | rc 1, stderr 1406 B, stdout 0 B | rc 0, root usage 2405 B | rc 1, stderr 96 B, stdout 0 B |
| `--help` / `-h` / `--help=true` (no subcommand) | rc 0, root help 1370 B | rc 0, root usage 2405 B | rc 0, root usage 2405 B (unchanged) |
| `status --help` / `status -h` / `status --help=true` | rc 0, `status`'s help 627 B | rc 0, 1604 B | rc 0, 1604 B (unchanged) |

What moved is the **class the item measured**: whether the command resolves and
runs at all (`--help=false status` now dials, 1 connection, rc 1), and the three
shorthand-cluster argvs that printed help instead of pflag's refusal. What did
**not** move is the help **document**: `--help=true <sub>` and `<sub> --help`
still print bpaf's usage document (1604 B for `status`) where Go prints cobra's
`Overview of all proxies status` (627 B). Reproducing that document means
reproducing cobra's command-help renderer over bpaf's metadata — command short
text, the `Flags:`/`Global Flags:` split, 30-column flag alignment, `-h, --help
help for status` — and it is a **flag-surface-wide** row, not a `--help` one:
`frpc status --help` (627 B vs 1604 B) and `frpc --help` (1370 B vs 2405 B) differ
for exactly the same reason and are **not** made worse here. It is left as the
separate, larger row the item named, and the byte counts are the honest
statement of where the two trees stand. Two sub-differences are *inside* the
matched class and are also not fixed:

* the shorthand refusal reproduces pflag's **line**, rc 1 and the stderr stream,
  but not cobra's trailing usage block: Go's stderr is 637 B for `-hc status`
  and 1351 B for `-hc`; frp-rs's is 41 B, because no frp-rs parse failure prints
  a usage block (measured: `frpc -c` is 40 B on stderr). The old `rc 0` help
  print is gone, which is the parity that matters for a script.
* `--help=<bool>` is refused with pflag's grammar and rc for out-of-grammar
  values (`--help=foo`, `--help=`, `--help=yes` → stderr 102 B, rc 1), where the
  base printed help; the **text** is frp-rs's spelling of pflag's message.

The implementation is two pre-parse passes in `frp-core/src/cli.rs`, both
reading the argv `rewrite_config_dash_values` and `hoist_leading_subcommand` have
already produced (`prepared_cli_argv` carries the order and why it is
load-bearing):

* `expand_help_bool_value_form` drops a `--help=<bool>` token when the argv's
  first bare word is a command this binary implements — so the command resolves
  and runs — and appends a bare `--help` at the **end** when the value is true,
  so the *subcommand's* help is what prints. It deliberately leaves the token in
  place when there is no command word (`--help=false -c cfg`, the pre-existing
  root divergence) or when the bare word is not a command
  (`--help=true notacommand` must stay bpaf's refusal, not become root help),
  and it never touches anything after a real `--`.
* `reject_pflag_shorthand_cluster_that_needs_a_value` prints pflag's
  `flag needs an argument: '<c>' in -<c>` on stderr and exits 1 for the argv bpaf
  answered with help: a trailing `-h<value-short>` cluster (`-hc`, `-hL`) whose
  value never arrived. Its input is the **expanded** argv, because the expansion
  is what knows a `--help=<bool>` token can be another flag's value — so
  `frpc -hc --help=false status` is left alone and `frpc -hc` (last after the
  hoist) is refused. It stays narrow on purpose: a bare `-c` with nothing after it
  is already a bpaf error with rc 1 on the right stream, and it is the `-h<short>`
  cluster that turns the same argv into a help print instead.
* **One predicate decides token ownership for all three passes.**
  `claims_the_next_token(token, context, root)` is what the walk, the attachment and the
  `--help=<bool>` expansion ask, so they cannot disagree: the two bare help spellings claim nothing
  (which is what makes a bare dangling short behind them reportable — `frpc -h -c` is pflag's line on
  stderr with rc 1, as Go, while `frpc -t -h` stays unreported because there `-h` **is** the value);
  an `-h<short>` cluster claims; a **long** claims only when it is in the derived
  `VALUE_TAKING_LONG_FLAGS` list; a **short** claims on pflag's rule (a single-dash token that is not
  `-v`). The list is derived from this file's `long("…") … .argument` chains and excludes every
  `go_bool_flag!` name and `--strict-config`, whose value branch is `.adjacent()` — attaching a
  separate token to one of those makes the **bool** parser refuse it, which is a measured regression
  class (`frps verify --dashboard_tls_mode -c CFG` was rc 1 with 0 B where Go and the base are rc 0
  with 114 B; `frpc tcp --disable-log-color -h`, `--ue -h`, `--uc -h`, `stcp --tls_enable -h` were
  errors where both trees print help). A name frp-rs does not register is deliberately **not** in the
  list even where Go accepts it. `--bind-port` is **not** an example of that: frp-rs registers both
  spellings (`frp-core/src/cli.rs` `svr_bind`, `long("bind-port").short('p').long("bind_port")`) and
  it **is** listed (`-` and `_` names both appear, because Go's `config.WordSepNormalizeFunc` folds
  one into the other). Measured with it listed: `frps verify --bind-port --help=false -c CFG` is
  **rc 1 on stderr** with `` couldn't parse `--help=false`: invalid digit found in string `` (68 B)
  where Go is rc 1 with 2191 B — the same rc and stream, and the attach is what gives pflag's
  faithful outcome instead of bpaf's help — and `--bind-port 7000 verify -c CFG` is rc 0 with 112 B
  on Go, the base and this head. The names this list deliberately omits are flags frp-rs's **own**
  parsers do not have at all. A token that already contains
  `=` claims nothing and is never re-attached.
* **The root short sets are per binary.** `frpc`'s run path is the only parser here with `-L`
  (frp-rs's alias for `--log-level`); `frps`'s root has `{c,p,t}` and every subcommand of both
  binaries has `{c,p,t}`. Sharing frpc's list with frps made `frps -hL` print a
  `flag needs an argument: 'L' in -L` for a short frps does not register; the split makes it
  bpaf's own rc 1 (stderr 45 B, base == head) while `frpc -hL` is rc 1 as Go.
* `attach_flag_shaped_values` joins a flag-shaped value to its flag with `=`,
  because bpaf classifies a token before it parses it: `frps -c CFG -t -h` reached
  bpaf as `-t` with no value plus a bare `-h`, so the server exited **0** with
  3571 B of help where Go hands `-h` to `--token`, loads the config and exits 1
  (measured: 36 B on stdout). `-t=-h` is the same flag and value to pflag. On
  `frpc` this is also what makes `frpc -c CFG -t -h` and `frpc tcp -c CFG -t -h`
  reach the config load instead of printing help — the two argv R2 measured as
  "Go runs, the head refuses".

Values go through `parse_go_bool`, the same `strconv.ParseBool` grammar as every
other bool flag here, so `1`/`0`/`t`/`f`/`T`/`F`/`TRUE`/`FALSE`/`True`/`False`
are accepted on the `=` spelling.

**Recorded residuals, each measured on Go v0.71.0 / base / head.** The sweep is
**262 argv** against Go v0.71.0, the base head and this head — **210 `frpc`** + **52 `frps`** —
with **0 regressions** and **70 moved to Go's `(rc, connection count, stdout empty)`**. Composition,
row by row, so every figure is re-derivable from the raw files:

| matrix | binary | rows | moved | help-document rows (all byte-identical) |
|---|---|---|---|---|
| `matrix.py` | frpc | 27 | 7 | 14 |
| `matrix2.py` | frpc | 58 | 13 | 27 |
| `matrix3.py` | frpc | 69 | 22 | 26 |
| `matrix4.py` | frpc | 20 | 6 | 7 |
| `matrix5.py` | frpc | 24 | 6 | 8 |
| `verifyrows.py` | frpc | 2 | 0 | 0 |
| `runrows.py` | frpc | 3 | 0 | 0 |
| `m6.py` | frpc | 7 | 2 | 3 |
| **frpc total** | | **210** | **56** | **85** |
| `frpsrows.py` | frps | 20 | 9 | 7 |
| `matrix5.py` | frps | 13 | 2 | 2 |
| `verifyrows.py` | frps | 8 | 0 | 0 |
| `runrows.py` | frps | 3 | 1 | 0 |
| `m6.py` | frps | 8 | 2 | 1 |
| **frps total** | | **52** | **14** | **10** |

That is **95 rows whose stdout is a help document, byte-identical between base and head** on `rc`,
connection count, stdout **and** stderr lengths — the recipe is *"stdout contains `Usage:` or
`Overview of`, and base == head on all four"*, and it is the recipe rather than a bare number that
makes it checkable (a wider recipe, "stdout is non-empty", gives 173 rows and 128 identical, which is
a different question). Two caveats about the counts themselves: `matrix4.py`'s **12 frps rows are
excluded** — they were stored with an `frpc` config, so they failed on `unknown field "serverAddr"`
and measure nothing about the frps surface — and 20 frpc labels (`N…`) appear in **both**
`matrix4.py` and `matrix5.py` with different configs, so the row count is a measurement count while
the distinct-label count is 190. This round adds `m7.py`'s 6 frps rows (2 moved), which would make
the totals 268 and 72. Every figure comes from `/tmp/probe/*.jsonl`, whose producers are
`matrix{,2,3,4,5}.py`, `m6.py`, `m7.py`, `frpsrows.py`, `verifyrows.py` and `runrows.py`.

Scored per surface, since one aggregate hid the frps half in two earlier rounds:

| surface | rows | agree with Go on `(rc, conns, stdout empty)` | residuals |
|---|---|---|---|
| `frpc` (all matrices) | 183 | 139 (48 of them moved by this change) | 44, of which **32 are unchanged from the base** |
| `frps` (20-row matrix) | 20 | **19** (10 moved) | 1: `--help=false -c CFG`, the root divergence below |
| `frps` `verify` (valid configs) | 10 (incl. 2 `frpc`) | 9 | 1: the run-path row in that fixture, whose `rc 3` is the `EXIT_AUTH` hardening below |
| `run` rows (hardening-safe configs) | 6 | 3 | 3: all `frpc tcp`, the pre-existing single-proxy flag requirement |

The seven `frps verify` rows measured with a valid config —
`--token --help=false`, `--bind-addr --help=false`, `-t --help=false`,
`--log_file --help=false`, `--log-level --help=false`, and the two controls — are
**byte-identical** to Go (116 B on stdout, rc 0). The two **`frpc verify`** rows
(`--allow-unsafe --help=false`, `--config-dir --help=false`) match Go on `rc`,
connection count and stream but **not** on bytes: the first line is Go's exact
sentence, and frp-rs then prints its three indented summary lines, which Go does
not (measured on a minimal config: Go stdout 52 B, frp-rs 104 B — the whole 52 B
delta is those lines). The `--config-dir` row's remaining behaviour is base ==
head (pre-existing). The `frpc tcp --proxy-name --help=false -c CFG` row is
worth stating precisely: the head is **byte-identical to the base's** `frpc tcp
--proxy-name=x -c CFG` (rc 1, 0 B on stdout, 73 B on stderr), i.e. the help flag
is inert; Go *starts* on both, and that gap is the pre-existing "frp-rs's
single-proxy commands require their own flags where Go falls back to the config
file" divergence, which the base shows with no help flag in argv at all.

| argv | Go | base | head | what is left |
|---|---|---|---|---|
| `--help=false -c cfg` | rc 1 | rc 0, root usage | rc 0, root usage | the pre-existing root divergence above, deliberately unchanged |
| `--help=0` / `--help=false` / `--help=false notacommand` / `--help=true notacommand` | rc 1 | rc 0 help | rc 0 help | unchanged: no command word, or a word that is not one |
| `-h -v -c` | rc 1 stderr | rc 0 help | rc 0 help | a value-taking short separated from the help short by a token that is not itself value-taking; bpaf's help short-circuit wins. The refusal pairs a bare help flag only with the short **immediately** after it |
| `-hLinfo` | rc 1 stderr | rc 0 help | rc 0 help | a trailing `-hL<value>` cluster: pflag hands `info` to `-L` and bpaf hands the token to `-h`. `-L` is frp-rs's alias for `--log-level` (`frp-core/src/cli.rs`, the `run_mode` parser's `log_level`) and **not** a Go shorthand — Go registers `log_level` with `StringVarP(..., "", ...)` (`pkg/config/flags.go:161`), so its own refusal is `unknown shorthand flag: 'L' in -L` |
| `frpc -hL` | rc 1 stderr (1351 B) | rc 0 root help | **rc 1 stderr (41 B)** | fixed on rc and stream; the message is pflag's `flag needs an argument: 'L' in -L` against Go's `unknown shorthand flag: 'L' in -L` **because frp-rs registers `-L` and Go does not** |
| `frpc status -hL`, `frpc tcp -hL` | rc 1 stderr | rc 0 help | rc 0 help | unchanged: those subcommands have no `-L`, so nothing is claimed and no missing-argument line is fabricated for a short frp-rs does not register there |
| `frps verify -hL` | rc 1, stderr 2108 B | rc 1, **stderr 45 B** (`\`-hL\` is not expected in this context`) | rc 1, **stderr 45 B** (same) | **base == head**, and the root split changed nothing here: `verify` is a subcommand, so `-L` was already out of its set. (An earlier revision of this table claimed "base rc 0 help / head rc 0 help" for this row; it is rc 1 on both.) |
| `frpc -hL` | rc 1, stderr 1351 B | rc 0 help | **rc 1, stderr 41 B** | **fixed on rc and stream** by the per-binary root split; the message is pflag's `flag needs an argument: 'L' in -L` against Go's `unknown shorthand flag: 'L' in -L`, **because frp-rs's run path registers `-L` and Go's does not** |
| `frpc -h -L` | rc 1, stderr 1351 B | rc 0 help | **rc 1, stderr 41 B** | the split spelling of the same pair |
| `frps -hL`, `frps -h -L` | rc 1, stderr 2375 B | rc 1, stderr 45 B / rc 0 help | rc 1, stderr 45 B / rc 0 help (**base == head**) | frps has no `-L` in frp-rs **or** Go, so nothing is fabricated; the root split is what keeps `frps -hL` from printing frpc's line |
| `frpc -hL -c CFG` | rc 1, stderr 1351 B | rc 0 help | rc 0 help | **unchanged from base, unrecorded until now**: the `-L` cluster claims the next token (`-c CFG`), so nothing dangles and bpaf prints help. Go is rc 1 |
| `frpc -L -h` | rc 1, stderr 1351 B | rc 0 help | **rc 1, stdout 78 B, stderr 0 B** | moved toward Go on rc: `-L` takes `-h` as `--log-level`'s value and the client then fails on the config path (78 B on stdout). Base ≠ Go, head ≠ Go on the stream — recorded |
| `frps -c CFG -t -h` (hardening-safe config, free `bindPort`) | **runs** (the harness signals it, −15, after the bounded wait; 331 B of startup log) | rc 0, root help | **rc 0, 2472 B of startup log — the server starts**, then exits on the harness's SIGTERM | **fixed**: the config load runs and the server starts, as Go's does. An earlier revision of this row recorded `rc 1` with `frps error: Address already in use (os error 48)` — a **harness artifact**, not this argv: with `bindPort = 0` frp-rs completes the port to 7000, so a row could collide with another test's server. Re-measured here with a fresh free `bindPort` per row |
| `frps -t -h`, `frps -p -h` (hardening-safe config) | rc 1, stdout 186 B / stderr 2438 B | rc 0, root help | rc 1, stdout 78 B / stderr 58 B | **fixed**: the config load runs as Go's does (the byte counts differ — frp-rs's loader wording, no cobra usage block) |
| `frps -t -c CFG` | rc 1, stderr 135–142 B (**path-dependent**: the message names the config path) | rc 1, stderr **96 B** (bpaf's `` `-t` requires an argument `` hint, a fixed string) | rc 1, stderr **111–118 B** (path-dependent) | same rc and stream; bpaf's particular hint does **not** come back, because `-t=-c` is what pflag does and the parser then refuses the leftover positional (`CFG`, which Go also never consumes). The byte counts move with the temp path, so the claim is the shape |
| `frps -c CFG -t -h` (**tokenless** config) | rc 1 | rc 0, root help | rc 3 | the `EXIT_AUTH`/3 empty-token hardening, which is its own recorded divergence: with `[auth] method = "token"` and a token in the file the head reaches the server start and exits 1 like Go |
| `-c cfg -- --help=false` | rc 1 stdout | rc 1 stderr | rc 1 stderr | the positional-argument class (Go ignores what follows `--`, frp-rs refuses it) |
| `--help=false status -c CFG` (port set) | rc 1, 1 conn, **stdout** 45 B | rc 0, 0 conn | rc 1, 1 conn, **stderr** 22 B | the admin status error's stream: frp-rs's `status query failed: …` goes to stderr on every status failure, port or not, unrelated to this flag |

**The help-rendering row is filed, not just named.** Reproducing cobra's document
is a flag-surface-wide renderer over bpaf's metadata (command short text, the
`Flags:`/`Global Flags:` split, 30-column alignment, `-h, --help  help for
<cmd>`), and it covers argv this item does not own: `frpc --help` (2405 B vs
1370 B) and every `frpc <sub> --help` (1604 B vs 627 B for `status`) differ for
the same reason on **both** trees' existing behaviour. It is a `TODO.md` item of
its own ("The help *document* is bpaf's, not cobra's"), with the ten per-surface
byte counts as its witness, so it is a tracked row rather than a sentence in this section.

Verified rather than assumed: `frpc --help`, `frpc -h`, `frpc --help=true`, every
`frpc <sub> --help`/`<sub> -h`, `frpc --help status`, `frpc --help notacommand`,
`frpc -h status`, `frpc -c --help`, `frpc status -c cfg -hc`, `frpc -hcx`,
`frpc -hc=x`, `frpc -hc status -c CFG`, `frpc --strict-config status -c cfg` and
`frpc -v status -c cfg` are all byte-identical to the base head (or differ only
in the documented help-document bytes). The unit rows are
`help_bool_value_form_rows_match_go`,
`help_bool_value_form_uses_go_bool_spellings` and
`shorthand_cluster_needing_a_value_is_detected` (`frp-core/src/cli.rs`); the
`frpc` integration lanes are untouched, so `env.FRPC_TINY_CLI_TESTS` stays `11`
and `env.FRPS_CLI_TESTS` stays `27` — those two are that round's values, not the
current ones: the `auth.method` round moved them to `13` and `29`
(`.github/workflows/ci.yml` is the single home; this paragraph is a record of
what the help-bool round left behind).

### Repository Invariants (`repo-health.sh`)


`bash scripts/repo-health.sh` mirrors the `health` CI job. On top of version
alignment it gates the `Docs` section: every `docs/*.md` and `docs/*/` must be
reachable from `docs/README.md`, and **backtick-delimited** repo paths anchored
at a known root (`src/`, `tests/`, `docs/`, `frp-core/`, …) in current docs or
source comments must still resolve — against the directory of the file that
names it first, then the nearest ancestor holding a `Cargo.toml` (the owning
crate root — so a test that names src/v2_handshake.rs means
frp-core/src/v2_handshake.rs), then the repo root. A `crate/feature` span such
as `frp-core/tls` is recognised as Cargo feature syntax, not a path.

The path scan is **tracked-files-only**: its file list comes from the git index
(`git ls-files -z`), i.e. the set a clean checkout tracks. Untracked and
gitignored local state — `.worktrees/`, `.superpowers/`, a nested worktree's
point-in-time backlog and archive prose, editor backups — is therefore never
scanned, so the local mirror does not fail merely because the mandated worktree
workflow is in use. The index supplies the file *list* while content is read
from the worktree, so a tracked file edited locally is gated at its current
content. Local index state is visible too, so the list is not *exactly* a clean
checkout's file set: an intent-to-add (`git add -N`) entry is scanned, and an
unmerged path is listed once per stage and collapsed by path. Submodule contents
are never scanned — the index lists only the gitlink, and CI does not initialise
submodules. Because the scan follows the index, an *untracked* local file that
names a dead path is not gated — deliberate, since CI runs on a clean checkout
where untracked is absent, so the gate's CI meaning is unchanged.

Only a tree with no `.git` entry at all — not even a dangling symlink or a
gitfile whose gitdir is gone — falls back to walking the filesystem (release
tarball, Docker build context), pruning `.git` and `target` at any depth. A tree
that has any such `.git` entry but whose index cannot be read is **not**
certified: the path scan exits 3 rather than silently walking, because a walk
would scan the gitignored state this gate exists to avoid. A sparse checkout, or
any worktree missing a tracked path, is likewise not certified — that path is a
read error, not a skip; a partial clone (`--filter=blob:none`) materialises every
tracked file and does pass. The scan's minimum-size floors apply to the walk path
as well, and the `git ls-files` call runs with `GIT_DIR`/`GIT_WORK_TREE`/
`GIT_INDEX_FILE`/`GIT_COMMON_DIR`/`GIT_OBJECT_DIRECTORY` and any `GIT_TRACE*`
removed so the list comes from the repository git resolves for that directory,
not from an inherited environment: `git rev-parse --show-toplevel` must equal the
working directory (`realpath` on both sides) or the path scan exits 3, which is what
stops an enclosing repository's index from certifying a cwd whose own `.git` is
invalid. (The guard identifies the tree by where git says it is; it does not
prove the index file itself belongs to that tree — a symlinked or foreign
`.git/index` is tampering outside this gate's threat model.)
Hit lines are sorted by path and then by line number rather than in the old
depth-first walk order (per-directory filename sort); the counts and the hit set
are unaffected.

This is deliberately **not** "every repo path named resolves": un-backticked
prose and tree diagrams are not scanned, spans with no locating root (`mux.rs`,
`control/mod.rs`) are counted and left to review, and a directory that still
exists but has been emptied is not detected (existence is all that can be
checked mechanically). Third-party vendored markdown (`vendor/*/README.md`) is
out of scope; the frp-rs-authored `vendor/*/README-FRP-RS.md` notes stay in.
Historical records (`docs/archive/`, `docs/history/`, dated audits) and the
point-in-time files `CHANGELOG.md`, `TODO.md`, `performance-audit.md` and
`docs/refactor-large-modules.md` are out of scope because they quote an older
tree on purpose; see [`../TODO.md`](../TODO.md).

The same run also cross-checks the **quantitative claims the live docs make**
against the source that produces each number, and prints the whole inventory with
a witness line (`file:line`) for every entry. It is a curated list, not a regex
sweep over "numbers in docs" — a general sweep reports every port, buffer size
and version in the tree. Each entry pins (file, exact claim wording, source); the
expected value is recomputed from that source on every run, so two stale copies
can never agree with each other. The list is **curated, not exhaustive**: it
catches only the claim wordings it enumerates, so a quantity restated in new
words, or stated in a new doc, is **not** detected. When you add or reword a
count in a live doc, add the matching entry in the same change — or, better,
point at the source instead of typing the number. One definition is shared so
claim and counter cannot drift: "test function" is one `#[test]`/`#[tokio::test]`
attribute that starts a line after optional indentation, parameterised or not
(comment mentions do not count). Raw test counts are deliberately **not** in the
curated set — they change whenever a test is added, so gating them would make
"add a test" fail the `health` job; the script prints them instead. Two further
things are deliberately **not** gated because a text match cannot establish them:
**client-plugin wiring** (whether the `virtual_net` start-up skip and the
work-conn handoff actually compile and run) and **fuzz-target enablement** (a
`#[cfg]`-disabled target reads the same as a live one). Both are covered by the
plugin/compat test suite and `scripts/compat-test.sh`, not by a grep — a gate
that claimed them would be certifying text, not behaviour. The inventory is meant
to be read at release time; a claim that no longer matches fails the `health` CI
job.

A tree the gate cannot measure is **not** certified. Every file that supplies an
*expected* value for an entry — `scripts/compat-test.sh`,
`scripts/protocol-matrix.sh`, `scripts/rust_comments.py`, `frp-core/Cargo.toml`,
the two bench sources and each vendored crate's manifest — is checked before it is
read. An input the tree does not carry prints a partial-tree line (a missing path,
or `vendor manifest missing: …`); one it cannot read names the reason
(`Permission denied`, `not a regular file`, `not valid UTF-8`); a crate source
directory with no `.rs` file is refused rather than counted as zero. The block then
exits 3, a source walk that cannot complete exits 2, and `repo-health.sh` maps both
to its own failure line and a red run — so a sparse checkout or an unreadable input
is reported as unmeasurable, never as "a live doc quotes a figure the tree no
longer matches".

The same rule holds for every other read in the script: a gate reports a source it
could not read rather than comparing an empty value. Named paths (the version
sources, each vendored manifest, `rust-toolchain.toml`, the workflow files) are read
through `read_regular` — one `python3` doing an `O_NONBLOCK` open plus `fstat` on
the same descriptor — so a path flipping between a regular file and a FIFO cannot
slip between a test and the open, and a FIFO's blocking `open()` is never reached
(the `health` runner has no `timeout` binary, so a shell-level bound is not
portable). The recursive source counts are one python walk with the same guard
instead of `find | xargs cat`, and `.git` is resolved *without* git: `HEAD`, the
common `config`, `index` and `commondir` must be regular files before any git call,
every git call is bounded (15 s there, 30 s in the path scan), and the git
environment is sanitised. A refusal prints the reason and never an `ok`; a scan
whose file set was incomplete prints `not evaluated`. Known, deliberate holes are
listed next to the code (a directory named `*.yml`, a symlinked directory under
`.github/workflows/`), and a workflow *path* containing a newline is refused outright rather than
scanned (fail-closed, with its own `FAIL` row). All six scan walks dedupe on `(st_dev, st_ino)`;
the two non-`.rs` walks fall back to `realpath` only when `stat` fails, so two names for one
*missing* target still collapse. `rs_texts` shares its inode set per measurement scope
(`<crate>/src` and the crate directory, so a file counted in both scopes is not read as a
duplicate), while the three inline `.rs` walks each hold one set over the `<crate>/src` scope; a
file reachable by two names is counted once **in the first crate in `CRATES`
order that claims its inode** — a hard link has no canonical name, so a cross-crate alias is
attributed to the earlier crate and the crate that owns the tracked name can under-count by that
file's lines (measured: `ln frp-server/src/lib.rs frp-core/src/zz_hl_rev.rs` gives frp-core
`70/76534` and frp-server `31/59122`, down from `32/59146`); no curated figure names a per-crate
total, so this cannot turn a gate green. The gate's exit-code mapping is pinned by
`scripts/tests/repo-health-fixtures.sh`
(its own step in the `health` job), which builds a throwaway tree and asserts both the process rc
and the `archive path scan failed (exit 3)` row.

## 6. Release Process

### Pre-release checklist

Run through this before tagging. Most of it is automated, but two items are not
covered by any gate and are the ones that have actually been missed before.

- [ ] **Version alignment** — `bash scripts/repo-health.sh` exits 0. This is a CI
      gate (the `health` job), but check it locally first: it covers the 5 crates,
      the `VERSION` constant, `scripts/download-frp-rs.sh` and the README.
- [ ] **Doc figures reconciled** — read the `Docs` section of the same
      `repo-health.sh` run and reconcile every `claimed … measured …` line with
      its witness `file:line`; the run already fails on any *enumerated* claim
      whose figure no longer matches, but a count reworded or added since the
      last pass is not covered, so skim the witness lines for a claim that has
      drifted in *meaning* (a stale number usually means the sentence around it
      is stale too).
- [ ] **Gates green on `main`** — `cargo fmt --all -- --check`,
      `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
      `cargo test --workspace --all-features`, the two `RUSTFLAGS="-D warnings"`
      tiny/micro tier checks, `bash scripts/compat-test.sh`
      against the matching Go frp release, `bash scripts/protocol-matrix.sh`, and
      the daily XTCP VPS matrix.
- [ ] **Notes written in the right place** — the user-facing summary in
      [`CHANGELOG.md`](../CHANGELOG.md), the detailed round record in
      [`docs/history/development-log.md`](history/development-log.md). Do not write
      the same detail twice (see the [docs conventions](README.md#conventions-for-these-docs)).
- [ ] **Security audit** —
      `cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195 --ignore RUSTSEC-2023-0071`
      and `cargo deny check`.
- [ ] **Vendored crates — the step no tool covers.** `[patch.crates-io]` pins
      `rustls`, `yamux` and `russh`, so **`cargo update` will not pick up upstream
      security releases for them**. Before every release:
      - check <https://github.com/rustls/rustls/releases> for 0.23.x security
        backports and re-vendor if needed (frp-rs patches TLS code — this is the
        highest-risk item on this list);
      - re-read each `vendor/*/README-FRP-RS.md` and confirm the patches still
        match the code and the exit condition has not arrived;
      - confirm the `health` job still reports a README for every vendored crate.
      *Exit condition to watch:* `vendor/rustls` can be deleted as soon as the
      workspace moves to rustls ≥ 0.24, which has `invalid_sni_policy` natively.
      As of 2026-09-17 that upgrade is **blocked upstream**: crates.io's
      `max_stable_version` is `0.23.45` and the only 0.24 artifact is the
      `0.24.0-dev.1` prerelease, so the trigger and plan are tracked in
      [`../TODO.md`](../TODO.md). The vendored line is current in the meantime
      (`0.23.45`, the GHSA-2mjx-qc3c-rqvc fix).
      *Owner:* the sole maintainer — there is no second reviewer for this repo
      (see the bus-factor item in the backlog), so this checklist line **is** the
      control.
- [ ] **Regenerate the Go-frp comparison table** —
      `bash scripts/compare-go-frp.sh --build --memory`, then replace the table in
      the README's "Why frp-rs?" section. The script verifies platform *and*
      version against the current `VERSION` and aborts on a mismatch, so it cannot
      produce the apples-to-oranges table the old hand-written one was: a
      cross-platform or cross-version comparison is not a measurement.
- [ ] **All four size tiers build**, and record the sizes with the platform and
      rustc version — the numbers in the README are meaningless without them.
- [ ] **Release binaries are built with the declared profile.** CI overrides
      LTO/opt-level for speed; CI artifact sizes do not reflect the release.

### Version Bumping

**frp-rs 自身版本号严格对齐 Go frp 的发布号** (mandatory): the version
equals the current compat target Go frp release — currently **0.71.0** — and
bumps only when Go frp releases a new number. Update the version in ALL
sync locations:

```bash
# All crates share the same version
# Update in:
#   Cargo.toml (workspace)
#   frp-core/Cargo.toml
#   frp-server/Cargo.toml
#   frp-client/Cargo.toml
#   frps/Cargo.toml
#   frpc/Cargo.toml
#   frp-core/src/lib.rs  (VERSION constant)
#   scripts/download-frp-rs.sh  (default version)
#   README.md
```

Exception: `frp-vnet` stays independent at `0.1.0`.

### Building Release Binaries

The release workflow (`.github/workflows/release.yml`) cross-compiles for 13 targets:

- **Linux**: x86_64, aarch64, armv7, arm, i686, riscv64gc — glibc builds for all six, musl only for x86_64/aarch64/armv7 (built with `cargo zigbuild`)
- **macOS**: x86_64, aarch64 -- native builds
- **Windows**: x86_64, aarch64 -- native builds

Each target produces three variants: full, tiny, and micro.

To build locally for your platform:

```bash
# Full
cargo build --release -p frps -p frpc

# Tiny
cargo build --release -p frps -p frpc --no-default-features --features tiny

# Micro
cargo build --release -p frps -p frpc --no-default-features --features micro
```

### UPX Compression

After building, compress with UPX for additional size reduction (optional):

```bash
upx --best --lzma target/release/frps target/release/frpc
```

UPX is not required -- the release profile already produces compact binaries via `opt-level=z`, `lto=fat`, and `strip=symbols`.

### Docker Image Publication

The Docker image is built from source in a multi-stage build (`docker/Dockerfile.source`):

```bash
# Build for frps (from repo root)
docker build --build-arg FRP_COMPONENT=frps -t frps:latest -f docker/Dockerfile.source .

# Build for frpc
docker build --build-arg FRP_COMPONENT=frpc -t frpc:latest -f docker/Dockerfile.source .
```

Also available: `frps-tiny`, `frpc-tiny`, `frps-micro`, `frpc-micro` variants. The release workflow (`.github/workflows/docker.yml`) builds and pushes multi-arch images for all 6 variants. The image uses a `scratch` base (~2 MB total) with a musl-static binary.

### Triggering a Release

Releases are triggered by pushing a version tag or manually via workflow dispatch:

```bash
# Tag and push (triggers .github/workflows/release.yml)
git tag v0.71.0
git push origin v0.71.0
```

The release workflow:
1. Builds all 13 targets (9 Linux via cargo-zigbuild + 2 macOS + 2 Windows)
2. Packages each as `.tar.gz` (Linux/macOS) or `.zip` (Windows)
3. Creates a GitHub Release with auto-generated notes
4. Uploads all artifacts

The Docker workflow runs separately (`.github/workflows/docker.yml`) and can be triggered manually or on release.

## Maintenance policy: feature surface

frp-rs has one maintainer and more surface than one maintainer can hold at full
Go parity. The policy is **tiered by maintenance effort, not by deletion**:
every surface below has an explicit decision and none is removed. The parity
debt behind each decision is in [`../TODO.md`](../TODO.md); the per-surface Go
comparison is in [`go-frp-compat-audit.md`](go-frp-compat-audit.md), and the
end-to-end evidence for the surfaces its scenarios actually cover is
[`scripts/compat-test.sh`](../scripts/compat-test.sh)
(see [§ Cross-Compatibility Tests](#cross-compatibility-tests)). That suite
does **not** cover every surface below: the frozen ones — SUDP, h2c, Windows
TUN, the non-default XTCP KCP+yamux plane — have no compatible scenario, and
`virtual_net` has none either. Their unfreeze conditions therefore rest on a
user report, an upstream Go change, or someone committing to test the surface —
never on a compat-matrix failure.

This is a **single-maintainer decision with no second reviewer** — the same
posture as the vendored-crate release check
([§ Pre-release checklist](#pre-release-checklist)) and the bus-factor item in
[`../TODO.md`](../TODO.md). It is recorded so a contributor can tell, for a
given surface, whether new Go-parity work is welcome, tolerated, or out of
scope.

| Tier | What a change means | Surfaces |
|---|---|---|
| **Keep** — full parity maintained | Go-parity work and cross-compat coverage are welcome; a regression is a bug. | TCP, UDP, HTTP, HTTPS, STCP, XTCP; V1 and V2 wire protocol; encryption and compression; TCP multiplexing; the transports (TCP, WebSocket, TLS, KCP, QUIC); OIDC; the dashboard; the SSH gateway; 9 of the 10 client plugins; the server-side `[[httpPlugins]]` manager. |
| **Opt-in** — best-effort | Fixes when a user needs them; no proactive parity investment. Staying out of the default build is intentional. | `vnet` (L3 VPN/TUN) and the `virtual_net` client plugin that rides it, `mimalloc`, `otel`, the frpc `admin` API. |
| **Freeze** — bug-fix only | No new Go-parity work, no Go-parity-only tests, no refactor. Not removed. | SUDP; h2c; Windows TUN; the non-default XTCP data plane (KCP+yamux). |

Three build-tier facts the tier names alone would hide. The dashboard is
**Keep** even though it is an opt-in Cargo feature (`frp-server/Cargo.toml:45`)
— it is part of the product, just not of every binary — while the SSH gateway
is default-on (`frp-server/Cargo.toml:44`). The `http-proxy` feature is
**default-on** (`frp-server/Cargo.toml:43`), so the server-side
`[[httpPlugins]]` manager is Keep; that same feature gates the frozen h2c module
(`frp-server/src/vhost.rs:23`), so h2c's freeze is a code-review rule rather
than a build gate — the frozen code still compiles into the default and tiny
tiers, and splitting the feature is not part of this policy. Finally, one of
the 10 client plugins, `virtual_net`, is the TUN-backed path with no listener
of its own (`frp-client/src/plugin/mod.rs:333`), so it follows the opt-in
`vnet` tier: it is named in the Opt-in row above and is the one client plugin
not counted in Keep.

One **CLI-surface** entry belongs in the same record, because it is the same kind
of decision and would otherwise read as an oversight: **cobra's `completion` and
`help` are not implemented on either binary, and `frps` now has a command list
they are absent from.** Measured on Go v0.71.0, `frps help` prints the root help
(rc 0) and `frps completion` prints its own help (rc 0); on this head both are
rc **1**, exactly as `frpc` has always answered them. The rc is the shared part,
not the wording: `frps` says `` `help` is not expected in this context `` /
`` `completion` is not expected in this context ``, while `frpc help` answers
with its positional-suggestion sentence (`no such command or positional: …`,
with a `did you mean` hint) because `frpc` has that parser and `frps` does not.
`FRPS_SUBCOMMANDS` (`frp-core/src/cli.rs`) therefore lists only `verify`, and the
list is pinned against the parser's branches in both directions by
`the_frps_command_list_is_exactly_the_parser_branches`. **Decision: recorded, not
implemented** — shell-completion scripts are not part of the product surface on
either binary, and implementing them for `frps` alone would add a new surface
with its own parity burden: **one script body per shell Go ships, and Go ships
four** — measured on Go v0.71.0, `frps completion --help` lists exactly `bash`,
`fish`, `powershell` and `zsh` under `Available Commands` — rather than fix a
parity gap. What would unfreeze it: a user report asking for completion, or
`frpc` gaining it first.

### Frozen surfaces, and what would unfreeze each

A freeze is a recorded decision, not neglect: each one names the evidence that
would lift it. Unfreezing moves the surface to **Keep** and resumes full parity
work; a bug fix on a frozen surface never needs an unfreeze.

- **SUDP** (`type = "sudp"`) — a distinct proxy type, not a UDP variant
  (`frp-core/src/config/loader.rs:1341`), with frp-rs-specific shared-port
  handling. Unfreeze if a deployment is shown to use it (a user report — the
  repo carries no usage telemetry) or if Go frp changes its SUDP/VisitorManager
  behaviour and compat breaks beyond what a fix can cover.
- **h2c** (`frp-server/src/vhost_h2c.rs`) — HTTP/2-cleartext decode/re-encode
  on the server vhost path. Unfreeze if Go frp changes its h2c handling (its
  `net/http` upgrade path or `pkg/util/vhost`) or a user report shows an h2c
  interop failure that must be re-derived from Go source.
- **Windows TUN** (`frp-vnet/src/tun_windows.rs`) — an explicit stub whose
  `open()` and `configure()` always error. Unfreeze if someone commits to the
  Wintun (`wintun.dll`) integration *and* can test on a Windows host; this
  repo's CI does not exercise vnet on Windows.
- **Non-default XTCP data plane (KCP+yamux)** — selected by `protocol = "kcp"`;
  the default is QUIC (`frp-core/src/config/client.rs:912`,
  `docs/config.md:668`). Unfreeze if a case is reported that the QUIC plane
  cannot serve (for example a hole punch where the QUIC handshake never
  completes but KCP does).

### How a surface moves between tiers

The maintainer makes the move in a commit that edits this section and the
matching item in [`../TODO.md`](../TODO.md), and the commit must name the
evidence: a user report of real use, a Go frp release-note or source change, or
a compat-matrix failure on that surface. Moving a surface into **Keep** means
deleting its "unfreeze if" line; that edit plus the reason is the whole change.
There is no second reviewer, so the recorded reason **is** the control.

## Dependency Policy

The dependency policy — the pre-approved tech stack table, the banned list and
the justification each new crate must carry — is maintained in exactly one
place: [**CLAUDE.md § Dependency Policy**](../CLAUDE.md#dependency-policy-mandatory).

It is not duplicated here because a second copy drifts: the copy that used to
live in this file had already fallen behind (it listed four vendored `yamux`
patches when there are five, and its TLS row omitted the pointer to
`vendor/rustls/README-FRP-RS.md`).

Adding a dependency: declare it in the workspace `[workspace.dependencies]`
table in the root `Cargo.toml`, then reference it by name (no version) from the
sub-crate.
