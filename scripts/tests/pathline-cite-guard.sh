#!/usr/bin/env bash
# pathline-cite-guard.sh — fail-closed gate over live `path:line` citations.
#
# Why this exists: a `path:line` cite in a live file is a claim about content at
# a position, and nothing checked it. `scripts/tests/todo-cite-guard.sh` checks
# only cites of TODO.md lines (and only that they land on an item header);
# `scripts/repo-health.sh` resolves backticked *paths* but does not look at the
# `:line` suffix at all. So one PR that inserts lines into a file silently rots
# every cite into that file, and a constant-offset repair only proves that one
# wrong offset was applied consistently (the measured case: PR #461 shifted 75
# cites into its own six touched files, and the renumbering that followed moved
# the repairs themselves).
#
# The enforced property is content, not arithmetic: every live cite has a
# committed expectation — the target file, the cited line (and the end of a
# `:N-M` range), and a fingerprint of the normalized text of that line — and the
# gate fails when the line at that number no longer carries that text, when the
# file or line no longer exists, or when a cite is added, deleted or renumbered
# without the expectation moving with it (expectations are keyed by the cite's
# raw token, so renumbering a cite reds).
#
# Scope — the same live / point-in-time classification `todo-cite-guard.sh` and
# `scripts/repo-health.sh` use:
#
#   * LIVE (scanned): everything else — source under the crate roots,
#     `scripts/**`, `.github/workflows/*.yml`, `CLAUDE.md`, `README.md`, the
#     top-level `docs/*.md`, nested crate `README.md`, `vendor/**`.
#   * POINT-IN-TIME (not scanned as citing files, and not validated as targets):
#     `TODO.md`, `CHANGELOG.md`, `performance-audit.md`,
#     `docs/refactor-large-modules.md` (the `SKIP_FILES` of
#     `scripts/repo-health.sh`) and everything under `docs/history/`,
#     `docs/archive/`, `docs/audit/`. Those documents record a round's own
#     numbering as of that round; rewriting them would falsify the record, and
#     they renumber on every round. Cites *into* them from live files are
#     counted and reported (`excluded`), never silently dropped; `TODO.md`
#     targets already have their own gate.
#
# Two cite classes are covered:
#
#   * ABSOLUTE — a token `PATH:N` or `PATH:N-M` whose PATH is path-shaped (it
#     carries a `/`, or its basename ends in one of `EXT`). A token that is not
#     path-shaped (`127.0.0.1:7400`, `03:17`, `7000:7000`, `docker/dockerfile:1`)
#     names no file and is ignored by construction, not by a noise blocklist.
#   * SHORTHAND — a bare `:N` or `:N-M` whose colon is not preceded by a path
#     character, a digit or another colon (so `"::1"`, `[::1]x]:8080` and
#     `"proxy port:8080"` are not cites). It resolves to the *nearest preceding
#     absolute citation*: the last path-shaped `PATH:N` token earlier on the
#     same line; failing that, the last such token on the nearest preceding line
#     reached by walking upwards while the block continues — the walk stops at a
#     blank line or at a line whose stripped text ends a sentence (`.`,`!`,`?`,
#     `。`). A bare `:N` with no such anchor in its block is prose (`0:00`, a
#     ratio, a port) and is not a cite.
#   * CONTINUATION — a `, N` / `, N-M` whose comma *directly* follows a citation
#     already recognised on the same line, with nothing but whitespace between
#     the token and the comma (`paths.rs:12, 13-14`). A comma that follows
#     anything else is not a citation, so ``(paths.rs:3157, a `[&str; 12]`)`` is
#     not one of `12`.
# The anchor (absolute, shorthand or continuation) decides the target *file* and
# the trailing token decides the *line*, so the two move independently — the
# fixture suite proves both directions.
#
# Resolution (three exact anchors, then a suffix search; a target is always a
# tracked file, so this gate cannot certify a path that is not in the tree):
#   1. relative to the citing file's directory,
#   2. relative to the owning crate root (nearest ancestor with `Cargo.toml`),
#   3. relative to the repository root,
#   4. the token's path as a suffix of exactly one tracked path inside the
#      owning crate, then of exactly one tracked path anywhere in the tree.
# A token that resolves nowhere is OUT OF TREE — `pkg/config/load.go:84` (Go
# frp), `axum-0.8.9/src/routing/method_routing.rs:1157` (a vendored crate), a
# Docker image tag — and is reported as an informational count. It names a file
# this repository does not contain, so there is nothing here to check it
# against; it is not a citation *of this repository*. A token that resolves to
# more than one tracked path is AMBIGUOUS: it is reported as an unvalidatable
# cite and its count is pinned (below).
#
# Fingerprints. The expectation stores `sha256(" ".join(line.split()))[:16]`:
# leading/trailing whitespace is trimmed and every internal run of whitespace is
# collapsed to one space. Nothing else is normalized — no comment-marker strip,
# no case fold — so a change to the cited line's text is a change to its
# fingerprint. A range cite fingerprints both endpoints, so a line inserted
# inside the range reds even when the start line is untouched.
#
# Fail-closed directions (each reds naming the citing file:line and the cite):
#   * the target file's line at the cited number no longer carries the recorded
#     text (the one-line-insert case), or is past EOF, or is blank (a blank line
#     carries no text to pin, so a citation of one cannot be validated),
#   * a cite in the tree has no expectation (added, renumbered, or a stale
#     `:NNN` whose anchor moved), or an expectation has no cite in the tree
#     (deleted or renumbered),
#   * the expectation file is missing, empty, unparseable, or carries no pinned
#     skip counts,
#   * the number of fingerprint-checked cites falls below the floor
#     (`PATHLINE_MIN_CITES`, default 400), so a broken file list, a bogus root
#     or a truncated checkout is a failure rather than a vacuous green (reported
#     beside any other violation, never instead of it),
#   * the count of unvalidatable cites (a path that resolves to more than one
#     tracked file) or of weakly anchored cites (the cited line's normalized
#     text is not unique in its target file, so a fingerprint match does not
#     prove the cite still points at the intended line — the class the original
#     scan lost four cites to) rose above its pinned count. Those pins can only
#     shrink, so a new unverifiable or weak cite has to be written as a
#     resolvable citation of a unique line instead of being silently certified,
#   * `git ls-files` fails (a partial tree is never certified), or python3 is
#     absent.
#
# The expectation table itself is never a citing file: its records carry the raw
# cite tokens verbatim, so scanning it would read every expectation as a
# citation. It is excluded by path, wherever it lives.
#
# Regeneration: `bash scripts/tests/pathline-cite-guard.sh --write` re-bakes the
# expectation file from the current tree. That is a **review surface, not
# tamper-proofing**: `--write` records whatever the tree says, so repairing a
# rotten cite by content and then re-baking, and laundering a rotten cite by
# re-baking alone, look identical in the data file. The distinction is the diff a
# reviewer reads, which is why `--derive` exists (it reports, per cite, whether
# the cited line still carries the text the citing line was written against and
# where that text lives now), why `--write` prints the added/removed records
# against the previous table, and why `.github/workflows/ci.yml` pins both this
# script's sha256 and the data file's sha256 — a regeneration is a two-file
# change a reviewer sees.
#
# Usage:
#   bash scripts/tests/pathline-cite-guard.sh              # gate this worktree
#   bash scripts/tests/pathline-cite-guard.sh --derive     # report rot (git blame)
#   bash scripts/tests/pathline-cite-guard.sh --write      # re-bake expectations
#   bash scripts/tests/pathline-cite-guard.sh [MODE] [REPO_ROOT] [DATA_FILE]
# The two positional arguments are the test seam the fixture suite
# (`scripts/tests/pathline-cite-fixtures.sh`) drives.
#
# Exit code: 0 when every cite matches its expectation; 1 otherwise.
set -uo pipefail

# Resolve this script through symlinks before deriving the repo root, the way
# the sibling suites do.
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

mode=check
positional=()
for arg in "$@"; do
  case $arg in
    --check) mode=check ;;
    --write) mode=write ;;
    --derive) mode=derive ;;
    --) ;;
    *) positional+=("$arg") ;;
  esac
done
ROOT=${positional[0]:-$(cd -P -- "$(dirname -- "$self")/../.." && pwd)}
DATA=${positional[1]:-$ROOT/scripts/tests/pathline-cite-expectations.txt}

if ! command -v python3 >/dev/null 2>&1; then
  printf 'FAIL  python3 not found — the cite gate cannot be evaluated (a green run needs it)\n' >&2
  exit 1
fi
if [ ! -d "$ROOT" ]; then
  printf 'FAIL  scan root is not a directory: %s\n' "$ROOT" >&2
  exit 1
fi
if [ "$mode" != write ] && [ ! -f "$DATA" ]; then
  printf 'FAIL  no expectation table to check cites against: %s is not a regular file\n' "$DATA" >&2
  printf 'FAIL  a missing expectation table must never read as a clean tree; regenerate it with\n' >&2
  printf 'FAIL    bash scripts/tests/pathline-cite-guard.sh --write\n' >&2
  exit 1
fi

# A floor on the fingerprint-checked cite count, so a broken file list (a git
# that exits 0 with no output, a bogus root, a truncated checkout) is a failure
# rather than a vacuous "0 cites, 0 violations, green". Far below the 483 live
# cites on the tree that added this gate; overridable only for the fixture
# suite's synthetic trees, which are legitimately smaller.
min_cites=${PATHLINE_MIN_CITES:-400}
# Fail closed on the floor itself: `0` (or a non-numeric, or a zero-padded
# zero) disables the check from inside, which is the shape the sibling suites
# reject for their own floors.
case $min_cites in
  ''|*[!0-9]*)
    printf 'FAIL  the cite floor is not a number (PATHLINE_MIN_CITES=%s); the gate cannot vouch for itself\n' \
      "$min_cites" >&2
    exit 1 ;;
esac
while [ "${min_cites#0}" != "$min_cites" ]; do min_cites=${min_cites#0}; done
if [ -z "$min_cites" ]; then
  printf 'FAIL  the cite floor is disabled (PATHLINE_MIN_CITES=%s); the gate cannot vouch for itself\n' \
    "${PATHLINE_MIN_CITES}" >&2
  exit 1
fi

out=$(PATHLINE_MIN_CITES="$min_cites" python3 -B - "$mode" "$ROOT" "$DATA" <<'PY'
import collections, hashlib, os, re, subprocess, sys

mode, root, data_path = sys.argv[1], sys.argv[2], sys.argv[3]
min_cites = int(os.environ.get("PATHLINE_MIN_CITES", "400"))

PIT_FILES = ("TODO.md", "CHANGELOG.md", "performance-audit.md",
             "docs/refactor-large-modules.md")
PIT_DIRS = ("docs/history/", "docs/archive/", "docs/audit/")
# Extensions a *slash-less* token must carry to be path-shaped at all. A
# timestamp (`2026-09-30T20`), a ratio, a port pair and a bare word have none of
# these, which is what keeps them out of the scan by construction.
EXT = (".rs", ".md", ".toml", ".yml", ".yaml", ".sh", ".json", ".txt", ".ini",
       ".lock", ".cfg", ".conf", ".py", ".go")
# `PATH:N` / `PATH:N-M`. The lookbehind refuses a token that is the tail of a
# longer path, host or word.
TOK_RE = re.compile(r'(?<![A-Za-z0-9_./-])([A-Za-z0-9_][A-Za-z0-9_./-]*?):(\d+)(?:-(\d+))?')
# Bare `:N` / `:N-M`. The lookbehind refuses a path tail, a digit (a port or a
# time), another colon (`"::1"`) and the two characters that make a port
# unambiguous inside this tree's string assertions (`[::1]x]:8080`).
BARE_RE = re.compile(r'(?<![A-Za-z0-9_./:\]"]):(\d+)(?:-(\d+))?')
# `, N` / `, N-M`: a comma continuation of the citation list that immediately
# precedes it. Only a comma that directly follows an already-recognised citation
# token (nothing but whitespace between the token and the comma) continues one,
# so `(paths.rs:3157, a [&str; 12])` is not a citation of `12`.
COMMA_RE = re.compile(r',\s*(\d+)(?:-(\d+))?')
# A sentence end, i.e. a block boundary for the shorthand walk-back. A blank
# line is the other boundary.
SENT_END = (".", "!", "?", "\u3002")


def point_in_time(rel):
    return rel in PIT_FILES or rel.startswith(PIT_DIRS)


def clean_env():
    env = dict(os.environ)
    for k in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_COMMON_DIR",
              "GIT_OBJECT_DIRECTORY"):
        env.pop(k, None)
    for k in list(env):
        if k.startswith("GIT_TRACE"):
            env.pop(k, None)
    return env


def tracked_files():
    """(tracked set, ordered list, [(relpath, lines)])."""
    env = clean_env()
    rels = None
    if os.path.exists(os.path.join(root, ".git")):
        try:
            out = subprocess.run(["git", "ls-files", "-z"], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as exc:
            print("FAIL  could not list tracked files in %s: %s" % (root, exc))
            sys.exit(1)
        if out.returncode != 0:
            print("FAIL  git ls-files failed in %s (rc %d); refusing to certify a "
                  "partial tree" % (root, out.returncode))
            sys.exit(1)
        rels = [p for p in out.stdout.split("\0") if p]
    if rels is None:
        rels = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".git", "target")]
            for fn in filenames:
                rels.append(os.path.relpath(os.path.join(dirpath, fn), root))
    files = []
    for rel in rels:
        full = os.path.join(root, rel)
        if not os.path.isfile(full):
            continue
        if os.path.getsize(full) > 2_000_000:
            continue
        try:
            with open(full, encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError):
            continue
        files.append((rel, text.split("\n")))
    return set(rels), sorted(rels), files


def crate_root(rel):
    """Nearest ancestor of the citing file holding a Cargo.toml ('.' at the top)."""
    d = os.path.dirname(os.path.join(root, rel))
    while True:
        if os.path.isfile(os.path.join(d, "Cargo.toml")):
            return os.path.relpath(d, root)
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def path_shaped(tok):
    return "/" in tok or os.path.splitext(os.path.basename(tok))[1] in EXT


def resolve(rel, tok, tracked, ordered, crate):
    """(target or None, verdict): exact | crate-suffix | suffix | ambiguous | foreign."""
    exact = [os.path.normpath(os.path.join(os.path.dirname(rel), tok)),
             os.path.normpath(tok)]
    if crate is not None:
        exact.insert(1, os.path.normpath(os.path.join(crate, tok)))
    for cand in exact:
        if cand in tracked:
            return cand, "exact"
    suffix = "/" + tok.lstrip("./")
    inside = [t for t in ordered
              if crate is not None and t.startswith(crate + "/") and t.endswith(suffix)]
    if len(inside) == 1:
        return inside[0], "crate-suffix"
    seen = set(inside)
    seen.update(t for t in ordered if t.endswith(suffix))
    if len(seen) == 1:
        return next(iter(seen)), "suffix"
    if len(seen) > 1:
        return None, "ambiguous"
    return None, "foreign"


def fingerprint(text):
    return hashlib.sha256(" ".join(text.split()).encode("utf-8")).hexdigest()[:16]


def scan(tracked, ordered, files):
    """The whole cite inventory of the tree."""
    lines_of = {}
    counts_of = {}

    def get_lines(rel):
        if rel not in lines_of:
            try:
                with open(os.path.join(root, rel), encoding="utf-8") as fh:
                    lines_of[rel] = fh.read().split("\n")
            except (UnicodeDecodeError, OSError):
                lines_of[rel] = None
            counts_of.pop(rel, None)
        return lines_of[rel]

    def occurrences(rel, norm):
        if rel not in counts_of:
            lines = get_lines(rel)
            counts_of[rel] = (collections.Counter(" ".join(x.split()) for x in lines)
                              if lines is not None else None)
        c = counts_of[rel]
        return 0 if c is None else c.get(norm, 0)

    result = dict(cites=[], excluded=[], ambiguous=[], weak=[], foreign=0,
                  shorthand=0, foreign_shorthand=0)

    for rel, lines in files:
        if point_in_time(rel):
            continue
        crate = crate_root(rel)
        anchors = {}
        for idx, line in enumerate(lines):
            found = []
            for m in TOK_RE.finditer(line):
                if not path_shaped(m.group(1)):
                    continue
                found.append((m.start(), m.group(0), m.group(1),
                              int(m.group(2)),
                              int(m.group(3)) if m.group(3) else None))
            if found:
                anchors[idx] = found

        def anchor_for(idx, col):
            same = [a for a in anchors.get(idx, []) if a[0] < col]
            if same:
                return same[-1]
            j = idx - 1
            while j >= 0:
                if lines[j].strip() == "":
                    return None
                if anchors.get(j):
                    return anchors[j][-1]
                if lines[j].rstrip() and lines[j].rstrip()[-1] in SENT_END:
                    return None
                j -= 1
            return None

        def record(citing, cite_line, col, raw, kind, target, line, end):
            if point_in_time(target):
                result["excluded"].append((rel, cite_line, raw, target, line, end, kind))
                return True
            tlines = get_lines(target)
            if tlines is None:
                result["ambiguous"].append((rel, cite_line, raw,
                                            "the target file is not readable as UTF-8"))
                return False
            start = None
            if 1 <= line <= len(tlines):
                start = " ".join(tlines[line - 1].split())
            fp = fingerprint(tlines[line - 1]) if start is not None else None
            fp_end = None
            end_ok = True
            if end is not None and end != line:
                if 1 <= end <= len(tlines):
                    fp_end = fingerprint(tlines[end - 1])
                else:
                    end_ok = False
            weak = bool(start) and occurrences(target, start) > 1
            cite = dict(cite=citing, cite_line=cite_line, col=col, raw=raw,
                        kind=kind, target=target, line=line, end=end, fp=fp,
                        fp_end=fp_end, weak=weak, end_ok=end_ok)
            result["cites"].append(cite)
            if weak:
                result["weak"].append(cite)
            return True

        def resolve_token(rel, lineno, col, raw, tok, target, verdict, line_no, end,
                          kind):
            """Resolve one citation token and record it; True when it counts as a
            shorthand/continuation cite."""
            if verdict == "foreign":
                result["foreign" if kind == "absolute" else "foreign_shorthand"] += 1
                return False
            if verdict == "ambiguous":
                result["ambiguous"].append(
                    (rel, lineno, raw, "%s resolves to more than one tracked path" % kind))
                return False
            if record(rel, lineno, col, raw, kind, target, line_no, end):
                if kind != "absolute":
                    result["shorthand"] += 1
                return True
            return False

        for idx, line in enumerate(lines):
            lineno = idx + 1
            # (end column, token, target, verdict) of every citation recognised so
            # far on this line, so a comma continuation can bind to the token it
            # extends.
            recognised = []
            for m in TOK_RE.finditer(line):
                tok = m.group(1)
                if not path_shaped(tok):
                    continue
                target, verdict = resolve(rel, tok, tracked, ordered, crate)
                resolve_token(rel, lineno, m.start(), m.group(0), tok, target, verdict,
                              int(m.group(2)),
                              int(m.group(3)) if m.group(3) else None, "absolute")
                recognised.append((m.end(), tok, target, verdict))
            for m in BARE_RE.finditer(line):
                anchor = anchor_for(idx, m.start())
                if anchor is None:
                    continue
                _, _, tok, _, _ = anchor
                target, verdict = resolve(rel, tok, tracked, ordered, crate)
                resolve_token(rel, lineno, m.start(), m.group(0), tok, target, verdict,
                              int(m.group(1)),
                              int(m.group(2)) if m.group(2) else None, "shorthand")
                recognised.append((m.end(), tok, target, verdict))
            for m in COMMA_RE.finditer(line):
                comma = m.start()
                prev = None
                for end_col, tok, target, verdict in recognised:
                    if end_col <= comma and line[end_col:comma].strip() == "":
                        if prev is None or end_col > prev[0]:
                            prev = (end_col, tok, target, verdict)
                if prev is None:
                    continue
                _, tok, target, verdict = prev
                resolve_token(rel, lineno, m.start() + 1, m.group(0).lstrip(",").strip(),
                              tok, target, verdict, int(m.group(1)),
                              int(m.group(2)) if m.group(2) else None, "continuation")
                recognised.append((m.end(), tok, target, verdict))
    return result


def read_data(path):
    """(records, header, error)."""
    records = []
    header = {}
    try:
        fh = open(path, encoding="utf-8")
    except OSError as exc:
        return None, None, "cannot read %s: %s" % (path, exc)
    with fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            if line.startswith("#"):
                m = re.match(r"#\s*counts:\s*(.*)$", line)
                if m:
                    for part in m.group(1).split():
                        if "=" in part:
                            k, v = part.split("=", 1)
                            header[k] = v
                continue
            fields = line.split("\t")
            if len(fields) != 9:
                return None, None, "record is not 9 tab-separated fields: %r" % line[:90]
            target, line_no, end, fp, fp_end, kind, cite, raw, cite_line = fields
            if not line_no.isdigit() or not cite_line.isdigit() or not fp:
                return None, None, "record is malformed: %r" % line[:90]
            records.append(dict(target=target, line=int(line_no),
                                end=None if end == "-" else int(end),
                                fp=fp, fp_end=None if fp_end == "-" else fp_end,
                                kind=kind, cite=cite, raw=raw,
                                cite_line=int(cite_line)))
    return records, header, None


def die(msg):
    print("FAIL  %s" % msg)
    sys.exit(1)


tracked, ordered, files = tracked_files()
# The expectation table is not a citing file: its own records carry the raw cite
# tokens verbatim, so scanning it would read every expectation as a citation.
data_rel = os.path.relpath(data_path, root) if os.path.isabs(data_path) else data_path
if data_rel.startswith(".."):
    data_rel = None
files = [(rel, lines) for rel, lines in files if rel != data_rel]
if not files:
    die("no scannable file in %s — refusing to certify an empty tree" % root)
res = scan(tracked, ordered, files)

if mode == "derive":
    env = clean_env()
    blame_cache = {}

    def blame_lines(rel):
        if rel not in blame_cache:
            table = {}
            try:
                out = subprocess.run(["git", "blame", "--line-porcelain", "--", rel],
                                     cwd=root, env=env, capture_output=True,
                                     text=True, timeout=300)
            except (OSError, subprocess.SubprocessError):
                out = None
            if out is not None and out.returncode == 0:
                for bl in out.stdout.split("\n"):
                    m = re.match(r"^([0-9a-f]{40}) \d+ (\d+)", bl)
                    if m:
                        table[int(m.group(2))] = m.group(1)
            blame_cache[rel] = table
        return blame_cache[rel]

    head_cache = {}

    def head_lines(rel):
        if rel not in head_cache:
            try:
                with open(os.path.join(root, rel), encoding="utf-8") as fh:
                    head_cache[rel] = fh.read().split("\n")
            except (UnicodeDecodeError, OSError):
                head_cache[rel] = []
        return head_cache[rel]

    def locate(target, text):
        if text == "":
            return []
        return [i for i, l in enumerate(head_lines(target), 1)
                if " ".join(l.split()) == text]

    def rebuild(c, new_line, new_end):
        if c["kind"] == "absolute":
            base = c["raw"].split(":")[0]
            out = "%s:%d" % (base, new_line)
        else:
            out = ":%d" % new_line
        if new_end is not None:
            out += "-%d" % new_end
        return out

    derive = []
    proposals = []
    cands_by_cite = {}
    for c in sorted(res["cites"], key=lambda c: (c["cite"], c["cite_line"], c["raw"])):
        sha = blame_lines(c["cite"]).get(c["cite_line"])
        if sha is None:
            derive.append(("no-blame", c, "git blame has no commit for the citing line"))
            continue
        try:
            out = subprocess.run(["git", "show", "%s:%s" % (sha, c["target"])],
                                 cwd=root, env=env, capture_output=True, text=True,
                                 timeout=120)
        except (OSError, subprocess.SubprocessError):
            out = None
        if out is None or out.returncode != 0:
            derive.append(("no-base", c, "the target file is absent at the citing commit"))
            continue
        old = out.stdout.split("\n")
        if not (1 <= c["line"] <= len(old)):
            derive.append(("no-base", c, "the cited line is absent at the citing commit"))
            continue
        want = " ".join(old[c["line"] - 1].split())
        if c["fp"] is not None and fingerprint(old[c["line"] - 1]) == c["fp"]:
            continue
        hits = locate(c["target"], want)
        head = head_lines(c["target"])
        head_text = (head[c["line"] - 1].strip()[:60]
                     if 1 <= c["line"] <= len(head) else "<past EOF>")
        if len(hits) == 1:
            new_line = hits[0]
            new_end = None
            if c["end"] is not None and c["end"] != c["line"]:
                if c["end"] <= len(old):
                    ehits = locate(c["target"], " ".join(old[c["end"] - 1].split()))
                    new_end = ehits[0] if len(ehits) == 1 else new_line + (c["end"] - c["line"])
                else:
                    new_end = new_line + (c["end"] - c["line"])
            proposals.append((c, rebuild(c, new_line, new_end), "content moved to :%d" % new_line))
            derive.append(("moved", c, "the base text is now at :%d" % new_line))
        else:
            cands_by_cite[(c["cite"], c["cite_line"], c["col"], c["raw"])] = hits
        if not hits:
            derive.append(("rewritten", c, "the base text %r is gone; head :%d is %r"
                           % (want[:46], c["line"], head_text)))
        elif len(hits) > 1:
            derive.append(("ambiguous", c, "the base text occurs at %s; head :%d is %r"
                           % (",".join(":%d" % h for h in hits[:6]), c["line"], head_text)))
    kinds = collections.Counter(d[0] for d in derive)
    print("derive: %d fingerprint-checked cite(s); %d still carry the text the citing "
          "line was written against" % (len(res["cites"]), len(res["cites"]) - len(derive)))
    print("derive: moved=%d ambiguous=%d rewritten=%d no-base=%d"
          % (kinds["moved"], kinds["ambiguous"], kinds["rewritten"], kinds["no-base"]))
    for kind, c, why in derive:
        print("  %-10s %s:%d cites %s (%s:%d) — %s"
              % (kind, c["cite"], c["cite_line"], c["raw"], c["target"], c["line"], why))
    # Machine-readable repair proposals: `PROPOSAL` rows are content-derived (the
    # text the cite was written against now lives at exactly one line), `MANUAL`
    # rows need a human to read the citing sentence. Nothing here edits a file.
    for c, new_raw, why in proposals:
        print("PROPOSAL\t%s\t%d\t%d\t%s\t%s\t%s"
              % (c["cite"], c["cite_line"], c["col"], c["kind"], c["raw"], new_raw))
    for kind, c, why in derive:
        if kind in ("moved", "no-base"):
            continue
        print("MANUAL\t%s\t%d\t%d\t%s\t%s\t%s\t%d\t%s"
              % (c["cite"], c["cite_line"], c["col"], c["kind"], c["raw"],
                 c["target"], c["line"], why))
        cands = cands_by_cite.get((c["cite"], c["cite_line"], c["col"], c["raw"]))
        if cands:
            print("CANDS\t%s\t%s" % (c["target"], " || ".join(
                "%d: %s" % (h, head_lines(c["target"])[h - 1].strip()[:90])
                for h in cands[:8])))
    sys.exit(0)

if mode == "write":
    rows = []
    for c in sorted(res["cites"], key=lambda c: (c["cite"], c["raw"], c["target"], c["line"])):
        rows.append("\t".join([
            c["target"], str(c["line"]),
            "-" if c["end"] is None else str(c["end"]),
            c["fp"] or "-", c["fp_end"] or "-", c["kind"], c["cite"], c["raw"],
            str(c["cite_line"])]))
    old_rows = None
    if os.path.isfile(data_path):
        old, _, err = read_data(data_path)
        if old is not None:
            old_rows = collections.Counter(
                "\t".join([r["target"], str(r["line"]),
                           "-" if r["end"] is None else str(r["end"]), r["fp"],
                           r["fp_end"] or "-", r["kind"], r["cite"], r["raw"],
                           str(r["cite_line"])]) for r in old)
    new_rows = collections.Counter(rows)
    with open(data_path, "w", encoding="utf-8") as fh:
        fh.write("# pathline-cite-guard expectations — generated; do not hand-edit.\n"
                 "# Regenerate with: bash scripts/tests/pathline-cite-guard.sh --write\n"
                 "# Regeneration is a review surface, not tamper-proofing: it records the\n"
                 "# current tree, so a rotten cite must be repaired by content first (run\n"
                 "# --derive to see which cites no longer carry the text they were written\n"
                 "# against). This file's sha256 and the guard's sha256 are both pinned in\n"
                 "# .github/workflows/ci.yml, so a regeneration is a two-file change.\n"
                 "#\n"
                 "# format: target<TAB>line<TAB>end|-<TAB>fp<TAB>fp_end|-<TAB>kind<TAB>"
                 "citing-file<TAB>raw-token<TAB>citing-line\n"
                 "#   fp = sha256(normalized target line)[:16]; normalization is trim plus\n"
                 "#        collapsing every internal whitespace run to one space\n"
                 "#   `checked` counts fingerprint-checked cites; `weak` are checked but\n"
                 "#        their cited line's text repeats in the target file; `ambiguous`\n"
                 "#        resolve to more than one tracked path. Both pins can only shrink.\n"
                 "#   counts: checked=%d weak=%d ambiguous=%d excluded=%d foreign=%d\n"
                 % (len(res["cites"]), len(res["weak"]), len(res["ambiguous"]),
                    len(res["excluded"]), res["foreign"]))
        for row in sorted(rows):
            fh.write(row + "\n")
    print("write: %d expectation(s) written to %s" % (len(rows), data_path))
    print("write: checked=%d weak=%d ambiguous=%d excluded=%d foreign=%d"
          % (len(res["cites"]), len(res["weak"]), len(res["ambiguous"]),
             len(res["excluded"]), res["foreign"]))
    if old_rows is not None:
        added, removed = new_rows - old_rows, old_rows - new_rows
        print("write: vs the previous table: %d added, %d removed, %d unchanged"
              % (sum(added.values()), sum(removed.values()),
                 sum((new_rows & old_rows).values())))
        for row in sorted(added):
            print("  + %s" % row.replace("\t", " | "))
        for row in sorted(removed):
            print("  - %s" % row.replace("\t", " | "))
    sys.exit(0)

records, header, err = read_data(data_path)
if err:
    die("cannot use %s: %s" % (data_path, err))
if not records:
    die("%s carries no expectation — a table with no record must never read as a "
        "clean tree" % data_path)

want = collections.Counter()
for r in records:
    want[(r["cite"], r["raw"], r["target"], r["line"], r["end"])] += 1
have = collections.Counter()
by_key = collections.defaultdict(list)
for c in res["cites"]:
    key = (c["cite"], c["raw"], c["target"], c["line"], c["end"])
    have[key] += 1
    by_key[key].append(c)

violations = []
for key, n in sorted((want - have).items()):
    for r in [x for x in records
              if (x["cite"], x["raw"], x["target"], x["line"], x["end"]) == key][:n]:
        violations.append(("%s:%d cites %s" % (r["cite"], r["cite_line"], r["raw"]),
                           "the expectation table records this cite but the tree does "
                           "not carry it (deleted or renumbered)"))
for key, n in sorted((have - want).items()):
    for c in by_key[key][:n]:
        violations.append(("%s:%d cites %s" % (c["cite"], c["cite_line"], c["raw"]),
                           "no expectation for this cite (added or renumbered); repair "
                           "it by content and regenerate with --write"))

checked = 0
remaining = collections.Counter(have)
for r in records:
    key = (r["cite"], r["raw"], r["target"], r["line"], r["end"])
    if remaining[key] <= 0:
        continue
    remaining[key] -= 1
    checked += 1
    label = "%s:%d cites %s (%s:%d)" % (r["cite"], r["cite_line"], r["raw"],
                                        r["target"], r["line"])
    try:
        with open(os.path.join(root, r["target"]), encoding="utf-8") as fh:
            tlines = fh.read().split("\n")
    except (UnicodeDecodeError, OSError) as exc:
        violations.append((label, "the target file cannot be read: %s" % exc))
        continue
    if not (1 <= r["line"] <= len(tlines)):
        violations.append((label, "the target line is past EOF (%s has %d lines)"
                           % (r["target"], len(tlines))))
        continue
    if tlines[r["line"] - 1].strip() == "":
        violations.append((label, "the target line is blank — a blank line carries no "
                                  "text to pin, so the cite cannot be validated"))
        continue
    got = fingerprint(tlines[r["line"] - 1])
    if got != r["fp"]:
        violations.append((label, "the target line no longer carries the recorded text "
                                  "(expected %s, found %s: %r)"
                           % (r["fp"], got, tlines[r["line"] - 1].strip()[:70])))
    if r["end"] is not None and r["end"] != r["line"] and r["fp_end"]:
        if not (1 <= r["end"] <= len(tlines)):
            violations.append((label, "the range end :%d is past EOF" % r["end"]))
        elif fingerprint(tlines[r["end"] - 1]) != r["fp_end"]:
            violations.append((label, "the range end line :%d no longer carries the "
                                      "recorded text" % r["end"]))

if checked < min_cites:
    # Reported alongside any other violation rather than instead of them: a
    # deleted cite can drop the checked count below the floor, and the point of
    # the failure is the deleted cite.
    violations.append(("only %d cite(s) verified (floor %d)" % (checked, min_cites),
                       "the scan is broken, not the tree clean — a broken file list, a bogus "
                       "root or a truncated checkout must never read as a clean tree"))

# Pinned counts: cites whose path resolves to more than one tracked file, and
# cites whose cited line text is not unique in its target file. Both pins live
# in the table header and can only shrink, so a new skip has to be written as a
# resolvable citation of a unique line instead of being silently certified.
def pin(name):
    v = header.get(name)
    return int(v) if v is not None and v.isdigit() else None


pin_ambiguous, pin_weak = pin("ambiguous"), pin("weak")
if pin_ambiguous is None or pin_weak is None:
    die("%s has no pinned 'ambiguous'/'weak' count in its header; a table without the "
        "skip pins cannot vouch for what it does not check" % data_path)
if len(res["ambiguous"]) > pin_ambiguous:
    violations.append(("%d ambiguous cite(s) (pinned %d)"
                       % (len(res["ambiguous"]), pin_ambiguous),
                       "a new cite resolves to more than one tracked file; write the "
                       "path that resolves: " +
                       "; ".join("%s:%d cites %s" % (a[0], a[1], a[2])
                                 for a in res["ambiguous"][:6])))
if len(res["weak"]) > pin_weak:
    violations.append(("%d weakly anchored cite(s) (pinned %d)"
                       % (len(res["weak"]), pin_weak),
                       "a new cite points at a line whose text repeats in its file, so a "
                       "fingerprint match cannot prove it still points at the intended "
                       "line; cite a unique line: " +
                       "; ".join("%s:%d cites %s" % (w["cite"], w["cite_line"], w["raw"])
                                 for w in res["weak"][:6])))

print("pathline-cite-guard: %d cite(s) checked (%d absolute, %d shorthand) across %d "
      "citing file(s) and %d target file(s)"
      % (len(res["cites"]), len(res["cites"]) - res["shorthand"], res["shorthand"],
         len(set(c["cite"] for c in res["cites"])),
         len(set(c["target"] for c in res["cites"]))))
print("pathline-cite-guard: unvalidatable (pinned, can only shrink): %d ambiguous "
      "path(s) [pin %d]; %d weakly anchored cite(s) [pin %d]"
      % (len(res["ambiguous"]), pin_ambiguous, len(res["weak"]), pin_weak))
print("pathline-cite-guard: excluded/reported, never silently ignored: %d cite(s) into "
      "the point-in-time set; %d out-of-tree token(s) (%d of them shorthand anchors) "
      "naming files this tree does not contain"
      % (len(res["excluded"]), res["foreign"], res["foreign_shorthand"]))
for rel, lineno, raw, why in res["ambiguous"]:
    print("  note  %s:%d cites %s — %s" % (rel, lineno, raw, why))
for c in res["weak"]:
    print("  note  %s:%d cites %s — %s:%d text is not unique in the target file"
          % (c["cite"], c["cite_line"], c["raw"], c["target"], c["line"]))
for label, why in violations:
    print("FAIL  %s — %s" % (label, why))
print("RESULT: %d cite(s) checked, %d violation(s)" % (checked, len(violations)))
sys.exit(1 if violations else 0)
PY
) && rc=0 || rc=$?
printf '%s\n' "$out"
exit "$rc"
