# frp-rs Documentation Index

Everything under `docs/`, and what to read when. If you are new to the project,
read the [main README](../README.md) first, then pick from the tables below.

## Reference — using frp-rs

| Document | What it covers |
|---|---|
| [Configuration Reference](config.md) | Every config field, with types, defaults and Go frp equivalents |
| [Proxy Type Guide](proxies.md) | When and how to use each proxy type (TCP, UDP, HTTP, STCP, XTCP, …) |
| [Client Plugins](client-plugins.md) | `http_proxy`, `socks5`, `static_file`, TLS termination, `virtual_net`, … |
| [Deployment Guide](deployment.md) | Systemd, Docker, TLS, monitoring, performance tuning |

## Development — working on frp-rs

| Document | What it covers |
|---|---|
| [Architecture](architecture.md) | **Canonical.** Wire protocol and message types, server accept loop and control plane, work-connection lifecycle, auth, encryption, transports, config normalization, XTCP hole punching, project/crate layout |
| [Developer Guide](developing.md) | Adding a proxy type, building and feature flags, debugging, testing, release process |
| [Refactoring the large modules](refactor-large-modules.md) | Where the code that is actually big is, and the seam to cut — **proposal, no code changed** |
| [`../CLAUDE.md`](../CLAUDE.md) | Agent/contributor **rules**: build matrix, versioning, workflow, dependency policy, invariants |
| [Technical Details](technical-details.md) | *Moved* — redirect stub to [Architecture](architecture.md), kept so old links keep working |

## Compatibility & audits

| Document | What it covers |
|---|---|
| [Go frp Compatibility Audit](go-frp-compat-audit.md) | Full cross-compat analysis against Go frp v0.71.0 |
| [Development Log](history/development-log.md) | Round-by-round hardening / audit history (findings and fixes) |
| [Feature Backlog (historical)](history/feature-backlog.md) | The former root `TODO.md` — parity/feature tracking, fully resolved |
| [Audit reports](audit/) | Dated point-in-time audit reports |
| [`../CHANGELOG.md`](../CHANGELOG.md) | User-facing release notes |

## Open work

| Document | What it covers |
|---|---|
| [`../TODO.md`](../TODO.md) | **Live backlog**: repo hygiene, documentation correctness, structural debt — each item with evidence and an acceptance test |

## `archive/` — archived working artifacts

> **Not current documentation.** `docs/archive/{plans,specs,notes,audit}/` holds
> 81 dated design documents and audit outputs (1.7 MB) captured *while* the
> corresponding work was in flight. They are kept as a historical record and for
> the raw evidence behind decisions, but they describe the state of the tree at
> their date, not today.
>
> This directory was named `docs/superpowers/` until it was moved to
> `docs/archive/` so its status is obvious from the path. Paths *inside* these
> documents still say `docs/superpowers/…` — they are deliberately left as
> written, since they are historical artifacts. See
> [`archive/README.md`](archive/README.md).

Read them only when you need the *reasoning* behind a past decision — for
example:

- [`archive/notes/2026-08-04-mimalloc-throughput-ab.md`](archive/notes/2026-08-04-mimalloc-throughput-ab.md) — why `mimalloc` stays opt-in, and §6 on the rustls SNI patch
- [`archive/notes/2026-08-04-xtcp-quic-sni-compat.md`](archive/notes/2026-08-04-xtcp-quic-sni-compat.md) — the XTCP QUIC SNI compatibility plan
- [`archive/notes/2026-08-size-optimization-analysis.md`](archive/notes/2026-08-size-optimization-analysis.md) — binary-size tier analysis

## Conventions for these docs

- Prefer **linking to code** (`file:line`) over restating it.
- Put **history** in [`history/development-log.md`](history/development-log.md)
  or [`../CHANGELOG.md`](../CHANGELOG.md) — not in reference docs. `CLAUDE.md`
  in particular is loaded into every agent context and has a hard 64 KB budget.
- **`CHANGELOG.md` is for users; `history/development-log.md` is the record.**
  A changelog entry says what changed and why it matters, in a few lines, and
  does not grow into a narrative. The round-by-round detail — every finding,
  adversarial review outcome, gate result and commit hash — belongs in the
  development log. When one change would be described in both, the changelog gets
  the summary and the log gets the detail; **do not write the detail twice**,
  because two copies drift and then neither can be trusted.
- **Do not hand-maintain numbers.** Countable figures (LOC, test counts, `unsafe`
  blocks, vendored versions) come from `bash scripts/repo-health.sh`. A figure typed
  into prose goes stale silently — the health table once claimed 17 `unsafe` blocks
  in `frp-core` while the tree had 21.
- **Test counts are not evidence of Go parity.** See
  [developing.md § What a green test run does and does not prove](developing.md#what-a-green-test-run-does-and-does-not-prove).
- Keep open work in [`../TODO.md`](../TODO.md), with evidence and a done-when.
