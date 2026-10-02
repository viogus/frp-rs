#!/usr/bin/env bash
# todo-cite-guard.sh — fail-closed gate over TODO.md line-number citations.
#
# Why this exists: `TODO.md` is a numbered ledger and every merge that inserts or
# removes a line renumbers it, so a cite written as a bare line number silently
# points at a different item — usually at *prose inside* some other item, which
# reads as plausible and is why five rounds of this train each re-derived cites
# by hand and each left a residue. The enforced property is deliberately weak and
# mechanical: **every live cite that names TODO.md and a line number must land on
# an item header line** (`^- \[[ x]\]`, outside any fenced code block), and every
# cite must be checkable. It does not attempt to match the cited item's title to
# the citing sentence: a text match cannot establish intent, and a gate that
# guessed would either miss real drift or red on honest prose. What it *does*
# establish is that a cite either resolves to an item's header or is reported by
# file:line.
#
# Scope — the live / point-in-time classification (the same one this PR's sweep
# used, and the one `scripts/repo-health.sh` already applies to path cites):
#
#   * LIVE (scanned): everything else — source comments under the crate roots,
#     `scripts/**`, `.github/workflows/*.yml`, `CLAUDE.md`, `README.md`, and the
#     top-level `docs/*.md` (including `docs/developing.md` and
#     `docs/deployment.md`), plus any nested `README.md` under a crate.
#   * POINT-IN-TIME (skipped): TODO.md itself, `CHANGELOG.md`,
#     `performance-audit.md`, `docs/refactor-large-modules.md` (the four
#     `SKIP_FILES` of `scripts/repo-health.sh`), and everything under
#     `docs/history/`, `docs/archive/` and `docs/audit/`. Those documents record
#     a round's own numbering as of that round — a past devlog row that cited the
#     closed tokenSource item was *correct then*, and rewriting it would falsify
#     the record. `CLAUDE.md` is deliberately NOT in this set: it is a live
#     instruction file loaded into every agent context, so its cites must resolve.
#
# The bare `:NNNN` continuation form is handled: a cite may be written as a
# full cite followed by a comma-separated `:NNNN` (or span a wrapped line,
# including a cite whose colon ends the line and whose number opens the next at
# any indentation), where the second number means the same ledger. A `:NNNN` is
# only read as a continuation when it sits within the same cite list — preceded
# on the same line by a full cite, or on a line that carries nothing but the
# `:NNNN` token (and optional trailing text) after a full or colon-only cite —
# and when the token is not itself the tail of some other `file:line` reference.
# A colon-only cite whose number is indented onto the next line is the same
# shape: the colon line is not a missing number, the continuation line is.
#
# Fail-closed directions (each reds with the offending file:line):
#   * a cite past EOF, before line 1, on a blank line, or on a mid-item body line
#     (the common drift);
#   * a cite whose target is header-shaped but sits inside a fenced code block
#     (documentation, not an item header), or a ledger with an unterminated fence;
#   * a citation attempt with no line number — the colon with nothing after it,
#     with whitespace before the colon, or with a non-numeric token after it.
#     One shape is deliberately exempt: a title-form cite (colon then a quote),
#     which names an item by text; the sweep converted the two live ones to
#     numbers, and a new one is prose by convention. A mention of TODO.md with no
#     colon at all is likewise prose, not an attempt;
#   * zero cites found at all, or a ledger with no item headers (both mean the
#     scan is broken, not that the tree is clean);
#   * a `git ls-files` that fails (a partial tree is never certified), a missing
#     ledger, a missing python3 interpreter, or a disabled/zero-padded floor.
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
# vacuous "0 cites, 0 violations, green". Far below any real checkout (84 live
# cite references on the tree that added this gate) and overridable only for the
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
# The `TODO.md` colon, with any whitespace between the name and the colon (a
# space before the colon is one of the F2 shapes). `\x60` spells a backtick
# without writing one: a lone backtick inside the shell heredoc starts a command
# substitution and breaks `bash -n`.
colon_re = re.compile("TODO\\.md\\s*:")
fence_re = re.compile("^\\s*(\\x60{3,}|~{3,})")

PIT_FILES = ("TODO.md", "CHANGELOG.md", "performance-audit.md",
             "docs/refactor-large-modules.md")
PIT_DIRS = ("docs/history/", "docs/archive/", "docs/audit/")


def is_point_in_time(rel):
    return rel in PIT_FILES or rel.startswith(PIT_DIRS)


def continuation_at(line):
    """True when a line carries nothing but an (indented) `:NNNN` continuation,
    optionally behind a comment marker and with trailing text."""
    rest = re.sub(r"^\s*(//[/!]?|#|\*|/\*|--)\s*", "", line)
    return bool(re.fullmatch(r":\d+\s*.*", rest))


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

# A header-shaped line *inside a fenced code block* is documentation, not an
# item header (the item anticipates a ledger-format change). Fences are tracked
# the way CommonMark opens one (three or more backticks or tildes); only
# un-fenced lines can be headers.
is_header = [False] * (len(todo) + 1)
fence = ""
for i, l in enumerate(todo, 1):
    fm = fence_re.match(l)
    if fm:
        marker = fm.group(1)[0]
        if fence == "":
            fence = marker
        elif fence == marker:
            fence = ""
        continue
    if fence == "" and hdr_re.match(l):
        is_header[i] = True
headers = [i for i in range(1, len(todo) + 1) if is_header[i]]
if not headers:
    print("FAIL  %s carries no item headers (open `- [ ]` or closed `- [x]`) — the ledger is not the "
          "ledger, so no cite can resolve" % todo_path)
    sys.exit(1)
# Every fence must close: an unterminated fence would make the rest of the
# ledger invisible to the scan and could hide a live cite target.
if fence != "":
    print("FAIL  %s has an unterminated fence; the ledger cannot be certified"
          % todo_path)
    sys.exit(1)

violations = []
checked = 0


def target_reason(n, raw):
    """The failure reason for a cite to ledger line `n`, or None when it lands
    on an item header."""
    if not (1 <= n <= len(todo)):
        return "past EOF (TODO.md has %d lines)" % len(todo)
    tgt = todo[n - 1]
    if is_header[n]:
        return None
    if hdr_re.match(tgt):
        return "header-shaped line inside a fenced block"
    if tgt.strip() == "":
        return "blank line"
    return "not an item header: %s" % tgt.strip()[:70]


for rel, lines in tracked_files():
    if is_point_in_time(rel):
        continue
    for idx, line in enumerate(lines):
        lineno = idx + 1
        prev = lines[idx - 1] if idx > 0 else None
        # A wrapped cite may end at the colon (the TODO.md colon alone on this
        # line, the number on the next): the colon form is line-final, and so is
        # a full cite whose line ends after the number.
        prev_wraps_cite = bool(prev is not None and trailing_re.search(prev)
                               and (full_re.search(prev)
                                    or colon_re.search(prev)))
        # (a) the numbered form: the name, a colon, the digits. When the digits
        # run into another word (`12abc`) the numbered match is only a prefix,
        # so the whole token is reported instead.
        for m in full_re.finditer(line):
            after = line[m.end():]
            if re.match(r"\w", after):
                checked += 1
                violations.append((rel, lineno, m.group(0) + after[:4],
                                   "unparseable cite (no decimal line number)"))
                continue
            checked += 1
            why = target_reason(int(m.group(1)), m.group(0))
            if why:
                violations.append((rel, lineno, m.group(0), why))
        # (b) bare `:NNNN` continuations. A bare number is only a continuation
        # when the line, or a wrapped cite on the previous line, introduced the
        # list; an unrelated `file:line` and a `:N: "text"` reference stay out.
        for m in bare_re.finditer(line):
            start = m.start()
            if start >= 8 and line[start - 8:start] == "TODO.md:":
                continue
            if start > 0 and (line[start - 1].isalnum() or line[start - 1] in "._-/"):
                continue
            indented_continuation = bool(prev_wraps_cite
                                         and not full_re.search(line)
                                         and continuation_at(line))
            if not (full_re.search(line[:start]) or indented_continuation):
                continue
            checked += 1
            why = target_reason(int(m.group(1)), m.group(0))
            if why:
                violations.append((rel, lineno, m.group(0), why))
        # (c) the shapes that are neither (a) nor (b). Three of these used to be
        # scanned past silently: a missing number, a space before the colon, and
        # a number wrapped onto the next line. The first two are citation
        # attempts and red here; the wrapped number is counted as a continuation
        # by (b) above, and the line that carries its colon is not re-counted
        # here. A title-form cite (colon then a quote) is prose by convention
        # and is the one exempt shape.
        # An indented `:N` on the next line is this cite's continuation, so the
        # colon itself is not a missing number: the continuation is counted on
        # that line by (b).
        next_line = lines[idx + 1] if idx + 1 < len(lines) else None
        wraps_forward = bool(next_line is not None and continuation_at(next_line))
        for m in colon_re.finditer(line):
            rest = line[m.end():]
            tok = rest.lstrip()
            if tok == "":
                if prev_wraps_cite or wraps_forward:
                    continue          # the wrapped number is counted by (b)
                checked += 1
                violations.append((rel, lineno, line[m.start():m.end()],
                                   "cite with no line number"))
                continue
            if tok[0] == '"':
                continue              # title-form citation, prose by convention
            if tok[0].isdigit():
                if m.group(0) != "TODO.md:":
                    checked += 1
                    violations.append((rel, lineno, m.group(0) + tok[:10],
                                       "malformed cite (whitespace before the colon)"))
                continue
            # Any other token is a citation attempt whose number is missing.
            checked += 1
            violations.append((rel, lineno, m.group(0) + tok[:10],
                               "cite with no line number"))

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
