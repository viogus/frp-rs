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
| [`../CLAUDE.md`](../CLAUDE.md) | Agent/contributor **rules**: build matrix, versioning, workflow, dependency policy, invariants |
| [Technical Details](technical-details.md) | *Moved* — redirect stub to [Architecture](architecture.md), kept so old links keep working |

## Compatibility & audits

| Document | What it covers |
|---|---|
| [Go frp Compatibility Audit](go-frp-compat-audit.md) | Full cross-compat analysis against Go frp v0.71.0 |
| [Development Log](history/development-log.md) | Round-by-round hardening / audit history (findings and fixes) |
| [Audit reports](audit/) | Dated point-in-time audit reports |
| [`../CHANGELOG.md`](../CHANGELOG.md) | User-facing release notes |

## `superpowers/` — archived working artifacts

> **Not current documentation.** `docs/superpowers/{plans,specs,notes,audit}/`
> holds ~90 dated design documents and audit outputs (≈1.9 MB) captured *while*
> the corresponding work was in flight. They are kept as a historical record and
> for the raw evidence behind decisions, but they describe the state of the tree
> at their date, not today.

Read them only when you need the *reasoning* behind a past decision — for
example:

- [`superpowers/notes/2026-08-04-mimalloc-throughput-ab.md`](superpowers/notes/2026-08-04-mimalloc-throughput-ab.md) — why `mimalloc` stays opt-in, and §6 on the rustls SNI patch
- [`superpowers/notes/2026-08-04-xtcp-quic-sni-compat.md`](superpowers/notes/2026-08-04-xtcp-quic-sni-compat.md) — the XTCP QUIC SNI compatibility plan
- [`superpowers/notes/2026-08-size-optimization-analysis.md`](superpowers/notes/2026-08-size-optimization-analysis.md) — binary-size tier analysis

## Conventions for these docs

- Prefer **linking to code** (`file:line`) over restating it.
- Put **history** in [`history/development-log.md`](history/development-log.md)
  or [`../CHANGELOG.md`](../CHANGELOG.md) — not in reference docs. `CLAUDE.md`
  in particular is loaded into every agent context and has a hard 64 KB budget.
