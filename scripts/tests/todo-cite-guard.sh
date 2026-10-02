#!/usr/bin/env bash
# todo-cite-guard.sh — fail-closed gate over `TODO.md:<n>` cross-file citations.
#
# Why this exists: `TODO.md` is a numbered ledger and every merge that inserts or
# removes a line renumbers it, so a cite written as a bare line number silently
# points at a different item — usually at *prose inside* some other item, which
# reads as plausible and is why five rounds of this train each re-derived cites
# by hand and each left a residue. The enforced property is deliberately weak and
# mechanical: **every live `TODO.md:<n>` cite must land on an item header line**
# (`^- \[[ x]\]`), and every cite must be checkable (in range, on a real line).
# It does not attempt to match the cited item's title to the citing sentence: a
# text match cannot establish intent, and a gate that guessed would either miss
# real drift or red on honest prose. What it *does* establish is that a cite
# either resolves to an item's header or is reported by file:line.
#
# Scope — the live / point-in-time classification (the same one this PR's sweep
# used, and the one `scripts/repo-health.sh` already applies to path cites):
#
#   * LIVE (scanned): everything else — source comments under the crate roots,
#     `scripts/**`, `.github/workflows/*.yml`, `CLAUDE.md`, `README.md`, and the
#     top-level `docs/*.md` (including `docs/developing.md` and
#     `docs/deployment.md`), plus any nested `README.md` under a crate.
#   * POINT-IN-TIME (skipped): `TODO.md` itself, `CHANGELOG.md`,
#     `performance-audit.md`, `docs/refactor-large-modules.md` (the four
#     `SKIP_FILES` of `scripts/repo-health.sh`), and everything under
#     `docs/history/`, `docs/archive/` and `docs/audit/`. Those documents record
#     a round's own numbering as of that round — a past devlog row that says
#     a cite to the closed tokenSource item was *correct then*; rewriting it
#     would falsify the record. `CLAUDE.md` is deliberately NOT in this set: it is a live
#     instruction file loaded into every agent context, so its cites must resolve.
#
# The bare `:NNNN` continuation form is handled: a cite may be written as a
# full cite followed by a comma-separated `:NNNN` (or span a wrapped line),
# where the second number means the same ledger. A `:NNNN` is only read as a
# continuation when it sits
# within the same cite list — preceded on the same line, or on the previous line,
# by a full `TODO.md:<n>` whose line ends at that cite — and when the token is not
# itself the tail of some other `file:line` reference.
#
# Fail-closed directions (each reds with the offending file:line):
#   * a cite past EOF, before line 1, or on a blank line;
#   * a cite on a mid-item body line (the common drift);
#   * a cite whose digits run into another word (a malformed token with a
#     trailing letter, say — distinct from a documentation mention written with
#     no digits at all, which is prose; see the unparseable-cite arm below);
#   * zero cites found at all, or a `TODO.md` with no item headers (both mean the
#     scan is broken, not that the tree is clean);
#   * `TODO.md` missing/unreadable, or a missing python3 interpreter.
#
# Usage:
#   bash scripts/tests/todo-cite-guard.sh                 # gate this worktree
#   bash scripts/tests/todo-cite-guard.sh [REPO_ROOT] [TODO_FILE]
# The two optional arguments are the test seam the fixture suite
# (`scripts/tests/todo-cite-guard-fixtures.sh`) drives: they let it point the
# same code at a synthetic tree and a synthetic ledger.
#
# Exit code: 0 when every live cite lands on a header; 1 otherwise.
set -uo pipefail

# Resolve this script through symlinks before deriving the repo root, the same
# way the sibling suites do, so invoking it through a link still finds `TODO.md`.
self=${BASH_SOURCE[0]:-$0}
case "$self" in
  */*) ;;
  *) if [ -e "$self" ]; then self=$PWD/$self; else self=$(command -v -- "$self") || {
       printf 'FAIL  cannot locate the guard: %s\n' "$0"; exit 1; }; fi ;;
esac
n=0
while [ -L "$self" ]; do
  [ "$n" -lt 40 ] || { printf 'FAIL  symlink loop resolving %s\n' "$0"; exit 1; }
  n=$((n + 1))
  dir=$(cd -P -- "$(dirname -- "$self")" && pwd) || exit 1
  link=$(readlink -- "$self") || exit 1
  case "$link" in
    /*) self=$link ;;
    *)  self=$dir/$link ;;
  esac
done
SELF_REAL=$self
ROOT=${1:-$(cd -P -- "$(dirname -- "$self")/../.." && pwd)}
TODO_FILE=${2:-$ROOT/TODO.md}

if ! command -v python3 >/dev/null 2>&1; then
  printf 'FAIL  python3 not found — the cite gate cannot be evaluated (a green run needs it)\n' >&2
  exit 1
fi
if [ ! -f "$TODO_FILE" ]; then
  printf 'FAIL  no ledger to check cites against: %s is not a regular file\n' "$TODO_FILE" >&2
  exit 1
fi
if [ ! -d "$ROOT" ]; then
  printf 'FAIL  scan root is not a directory: %s\n' "$ROOT" >&2
  exit 1
fi

# A floor on the scanned cite count, so a broken file list (a git that exits 0
# with no output, a bogus root, a truncated checkout) is a failure rather than a
# vacuous "0 cites, 0 violations, green". Far below any real checkout (82 live
# occurrences on the tree that added this gate) and overridable only for the
# fixture suite's synthetic trees, which are legitimately smaller.
min_cites=${TODO_CITE_MIN:-20}
# Fail closed on the floor itself: a floor of 0 (or a non-numeric one, or a
# zero-padded zero) disables the check from inside, which is the shape the
# sibling suites reject for their own `MIN_CHECKS`.
case $min_cites in
  ''|*[!0-9]*)
    printf 'FAIL  the cite floor is not a number (TODO_CITE_MIN=%s); the gate cannot vouch for itself\n' \
      "$min_cites" >&2
    exit 1 ;;
esac
while [ "${min_cites#0}" != "$min_cites" ]; do min_cites=${min_cites#0}; done
if [ -z "$min_cites" ]; then
  printf 'FAIL  the cite floor is disabled (TODO_CITE_MIN=%s); the gate cannot vouch for itself\n' \
    "${TODO_CITE_MIN}" >&2
  exit 1
fi
TODO_CITE_MIN=$min_cites

out=$(TODO_CITE_MIN="$min_cites" python3 -B - "$ROOT" "$TODO_FILE" <<'PY'
import os, re, subprocess, sys

root, todo_path = sys.argv[1], sys.argv[2]
min_cites = int(os.environ.get("TODO_CITE_MIN", "20"))

hdr_re = re.compile(r"^- \[[ x]\]")
full_re = re.compile(r"TODO\.md:(\d+)")
bare_re = re.compile(r":(\d+)")
# Wrapped continuation: line N is a cite and nothing else meaningful follows it.
# The class is spelled `\W` (not an explicit list) so this file's bytes carry no
# stray punctuation the shell could trip on.
trailing_re = re.compile(r"\W*$")

PIT_FILES = ("TODO.md", "CHANGELOG.md", "performance-audit.md",
             "docs/refactor-large-modules.md")
PIT_DIRS = ("docs/history/", "docs/archive/", "docs/audit/")


def is_point_in_time(rel):
    return rel in PIT_FILES or rel.startswith(PIT_DIRS)


def tracked_files():
    """(relpath, lines) for every scannable tracked file, git first."""
    env = dict(os.environ)
    for k in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_COMMON_DIR",
              "GIT_OBJECT_DIRECTORY"):
        env.pop(k, None)
    for k in list(env):
        if k.startswith("GIT_TRACE"):
            env.pop(k, None)
    rels = None
    if os.path.exists(os.path.join(root, ".git")):
        try:
            out = subprocess.run(["git", "ls-files", "-z"], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=120)
            if out.returncode != 0:
                print("FAIL  git ls-files failed in %s (rc %d); refusing to certify a "
                      "partial tree" % (root, out.returncode))
                sys.exit(1)
            rels = [p for p in out.stdout.split("\0") if p]
        except (OSError, subprocess.SubprocessError) as exc:
            print("FAIL  could not list tracked files in %s: %s" % (root, exc))
            sys.exit(1)
    if rels is None:
        rels = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".git", "target")]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rels.append(os.path.relpath(full, root))
    out = []
    for rel in rels:
        full = os.path.join(root, rel)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, encoding="utf-8") as fh:
                out.append((rel, fh.read().split("\n")))
        except (UnicodeDecodeError, OSError):
            continue
    return out


try:
    todo = open(todo_path, encoding="utf-8").read().split("\n")
except OSError as exc:
    print("FAIL  cannot read %s: %s" % (todo_path, exc))
    sys.exit(1)

headers = [i for i, l in enumerate(todo, 1) if hdr_re.match(l)]
if not headers:
    print("FAIL  %s carries no item headers (^- \\[[ x]\\]) — the ledger is not the "
          "ledger, so no cite can resolve" % todo_path)
    sys.exit(1)

violations = []
checked = 0

for rel, lines in tracked_files():
    if is_point_in_time(rel):
        continue
    for idx, line in enumerate(lines):
        lineno = idx + 1
        # Full cites.
        for m in full_re.finditer(line):
            checked += 1
            n = int(m.group(1))
            if not (1 <= n <= len(todo)):
                violations.append((rel, lineno, m.group(0),
                                   "past EOF (TODO.md has %d lines)" % len(todo)))
                continue
            tgt = todo[n - 1]
            if not hdr_re.match(tgt):
                if tgt.strip() == "":
                    why = "blank line"
                else:
                    why = "not an item header: %s" % tgt.strip()[:70]
                violations.append((rel, lineno, m.group(0), why))
        # Bare `:NNNN` continuations.
        prev_is_cite = idx > 0 and trailing_re.search(lines[idx - 1]) \
            and full_re.search(lines[idx - 1])
        for m in bare_re.finditer(line):
            start = m.start()
            # Skip the `:NNNN` that belongs to a `TODO.md:` already matched.
            if start >= 8 and line[start - 8:start] == "TODO.md:":
                continue
            # Skip any other `file:line` reference (the char before the colon is
            # a path/identifier character).
            if start > 0 and (line[start - 1].isalnum() or line[start - 1] in "._-/"):
                continue
            # Only a continuation when this line's own cite list already started
            # (a full cite earlier on this line, or a wrapped one above).
            if not (full_re.search(line[:start]) or (prev_is_cite and not full_re.search(line))):
                continue
            checked += 1
            n = int(m.group(1))
            if not (1 <= n <= len(todo)):
                violations.append((rel, lineno, m.group(0),
                                   "past EOF (TODO.md has %d lines)" % len(todo)))
                continue
            tgt = todo[n - 1]
            if not hdr_re.match(tgt):
                if tgt.strip() == "":
                    why = "blank line"
                else:
                    why = "not an item header: %s" % tgt.strip()[:70]
                violations.append((rel, lineno, m.group(0), why))
        # Unparseable cite — a citation attempt whose digits run straight into
        # another word (a trailing letter, say). A mention written without a
        # digit at all (a bracketed placeholder, or a word like `foo`) is prose,
        # not a citation attempt: this repo's documentation and this gate's own
        # comments quote that form on purpose, and a rule that red them would
        # leave no way to describe the rule. The number that follows a cite in a
        # `file:line: "text"` reference is not a continuation either, so the
        # colon-number arm above skips a `:N` whose colon is preceded by a word
        # character or a path separator.
        for m in re.finditer(r"TODO\.md:\d+[A-Za-z_]", line):
            checked += 1
            violations.append((rel, lineno, m.group(0)[:50],
                               "unparseable cite (no decimal line number)"))

if checked < min_cites:
    print("FAIL  only %d live cite(s) found (floor %d) — the scan is broken, not the "
          "tree clean" % (checked, min_cites))
    sys.exit(1)

print("checked %d live cite line reference(s) against %s (%d item headers)"
      % (checked, os.path.relpath(todo_path, root) if todo_path.startswith(root) else todo_path,
         len(headers)))
for rel, lineno, raw, why in violations:
    print("FAIL  %s:%d cites %s — %s" % (rel, lineno, raw, why))
print("RESULT: %d cite(s) checked, %d violation(s)" % (checked, len(violations)))
sys.exit(1 if violations else 0)
PY
) && rc=0 || rc=$?
printf '%s\n' "$out"
exit "$rc"
