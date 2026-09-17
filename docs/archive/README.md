# Archive — historical working artifacts

**These are not current documentation.** Everything under this directory is a
dated, point-in-time artifact captured *while* the corresponding work was in
flight: design specs, implementation plans, audit outputs and investigation
notes. They describe the state of the tree at their date, not today.

This directory was named `docs/superpowers/` until it was renamed to
`docs/archive/`, so that its status is evident from the path rather than only
from a note in an index.

## Layout

| Directory | Contents |
|---|---|
| `plans/` | Implementation plans (task-by-task breakdowns) |
| `specs/` | Design specs that plans were written against |
| `notes/` | Investigation and measurement notes (A/B results, audits, analysis) |
| `audit/` | Raw audit finding sets and triage reports (incl. JSON) |

## When to read these

Only when you need the **reasoning** behind a past decision — why a dependency
stays opt-in, why a compatibility divergence was accepted, what a measurement
actually showed. For how the system works *today*, use
[`../architecture.md`](../architecture.md); for the rules, [`../../CLAUDE.md`](../../CLAUDE.md);
for release history, [`../../CHANGELOG.md`](../../CHANGELOG.md) and
[`../history/development-log.md`](../history/development-log.md).

## Note on paths inside these documents

Path references **inside** these files still say `docs/superpowers/…`, and
references to the `superpowers:` skill namespace (e.g.
`superpowers:subagent-driven-development` in plan preambles) are unchanged.

Both are deliberate: these are historical documents, and rewriting their
contents would falsify the record. Translate a path by replacing
`docs/superpowers/` with `docs/archive/` — the internal structure
(`plans/`, `specs/`, `notes/`, `audit/`) is preserved exactly, so relative links
between these files still resolve.

Links pointing *into* the archive from current docs were updated, so nothing in
the live documentation is broken by the move.
