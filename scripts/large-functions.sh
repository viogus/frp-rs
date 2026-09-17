#!/usr/bin/env bash
# large-functions.sh — where is the code that is actually big?
#
# Why this exists: the backlog prioritised refactoring by raw `wc -l`, which is
# misleading twice over — inline `#[cfg(test)] mod` blocks are counted as if they
# were production code, and the biggest functions are dominated by comments (this
# codebase documents its Go-parity reasoning inline, on purpose). `poll_read` in
# `control/bridge.rs`, for example, is 664 lines of which only 236 are code.
#
# Reports:
#   1. per-file lines: total / inline-test / production
#   2. the largest production functions, measured in CODE lines (comments and
#      blanks excluded)
#
# Usage:
#   bash scripts/large-functions.sh            # default: top 12 functions
#   bash scripts/large-functions.sh --top 25
#
# Read-only; never fails the build. See docs/refactor-large-modules.md.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

TOP=12
[ "${1:-}" = "--top" ] && TOP="${2:-12}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found — cannot measure"
  exit 0
fi

python3 - "$TOP" <<'PY'
import os
import re
import sys

TOP = int(sys.argv[1])
ROOTS = ('frp-core/src', 'frp-server/src', 'frp-client/src', 'frp-vnet/src')
FN = re.compile(r'^(\s*)(?:pub(?:\([^)]*\))?\s+)?(?:const\s+|async\s+|unsafe\s+)*fn\s+([A-Za-z0-9_]+)')
TEST_ATTR = re.compile(r'\s*#\[cfg\(test\)\]')
MOD_LINE = re.compile(r'\s*(?:pub\s+)?mod\s+\w+')


def test_blocks(lines):
    """(start, end) index pairs of each `#[cfg(test)] mod` block, brace-matched."""
    out = []
    i, n = 0, len(lines)
    while i < n:
        if TEST_ATTR.match(lines[i]):
            j = i
            while j < n and not MOD_LINE.match(lines[j]):
                j += 1
            if j >= n:
                break
            depth, k, started = 0, j, False
            while k < n:
                for ch in lines[k]:
                    if ch == '{':
                        depth += 1
                        started = True
                    elif ch == '}':
                        depth -= 1
                if started and depth <= 0:
                    break
                k += 1
            out.append((i, k))
            i = k + 1
        else:
            i += 1
    return out


def is_test(idx, blocks):
    return any(a <= idx <= b for a, b in blocks)


def fn_body_end(lines, start):
    """Index just past the `}` that closes the fn starting at `start`.

    Measuring a function as "distance to the next `fn`" is wrong: type and const
    definitions between two functions get charged to the first one. That reported
    `health_check_monitored` (really 3 lines) as 434, and a nested 19-line
    `record_plugin` as 212. Brace-matching the body is the honest measure.

    Skips `//`, `/* */`, and string/char literals so braces inside them do not
    count. Returns None if the body never closes.
    """
    depth, seen_open = 0, False
    i, n = start, len(lines)
    in_block_comment = False
    while i < n:
        line = lines[i]
        j = 0
        while j < len(line):
            c = line[j]
            if in_block_comment:
                if c == '*' and j + 1 < len(line) and line[j + 1] == '/':
                    in_block_comment = False
                    j += 2
                    continue
                j += 1
                continue
            if c == '/' and j + 1 < len(line) and line[j + 1] == '/':
                break                      # rest of line is a comment
            if c == '/' and j + 1 < len(line) and line[j + 1] == '*':
                in_block_comment = True
                j += 2
                continue
            if c == '"':
                j += 1
                while j < len(line):
                    if line[j] == '\\':
                        j += 2
                        continue
                    if line[j] == '"':
                        break
                    j += 1
                j += 1
                continue
            if c == "'":
                # Rust has lifetimes (`'static`, `'a`) as well as char literals.
                # Treating every `'` as a char literal swallows everything up to
                # the next `'`, which corrupts brace counting — it made
                # `frp-server/src/service.rs::run` look like 940 lines, and
                # `frp-core/src/transport/mod.rs`'s `debug_name` like 1042.
                if j + 2 < len(line) and line[j + 1] == '\\':
                    j += 3                      # '\n'-style escape
                    continue
                if j + 2 < len(line) and line[j + 2] == "'":
                    j += 3                      # 'x'-style char literal
                    continue
                j += 1                          # lifetime — ordinary code
                continue
            if c == '{':
                depth += 1
                seen_open = True
            elif c == '}':
                depth -= 1
                if seen_open and depth == 0:
                    return i + 1
            j += 1
        i += 1
    return None


files = []
for root in ROOTS:
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            if not name.endswith('.rs'):
                continue
            # A whole-file test module (`config/tests.rs`) carries no
            # `#[cfg(test)]` inside it — the attribute is on the `mod` that
            # includes it — so excluding by attribute alone miscounts it as
            # production. 6005 "production" lines turned out to be a test file.
            if name == 'tests.rs' or ('%stests%s' % (os.sep, os.sep)) in dirpath + os.sep:
                continue
            files.append(os.path.join(dirpath, name))

per_file = []
fns = []
for path in sorted(files):
    try:
        lines = open(path, encoding='utf8', errors='ignore').read().split('\n')
    except OSError:
        continue
    blocks = test_blocks(lines)
    prod_idx = [i for i in range(len(lines)) if not is_test(i, blocks)]
    prod = len(prod_idx)
    total = len(lines)
    per_file.append((prod, total, total - prod, path))

    starts = [(m.group(2), i) for i in prod_idx
              for m in [FN.match(lines[i])] if m]
    for name, st in starts:
        end = fn_body_end(lines, st)          # brace-matched, see below
        # Test the body's LAST line, not `end`: `end` is the index just past the
        # closing brace, so when a `#[cfg(test)] mod` starts on the very next
        # line an inclusive test on `end` silently drops the function. That hid
        # `login.rs::authenticate` (510 code lines, the 4th largest in the repo).
        if end is None or is_test(end - 1, blocks):
            continue
        seg = lines[st:end]
        code = sum(1 for l in seg if l.strip() and not l.strip().startswith('//'))
        fns.append((code, end - st, name, path, st + 1))

per_file.sort(reverse=True)
print("Per-file lines (inline `#[cfg(test)] mod` blocks excluded)")
print(f"  {'production':>10} {'total':>8} {'test':>8}  file")
for prod, total, test, path in per_file[:14]:
    print(f"  {prod:10d} {total:8d} {test:8d}  {path}")

fns.sort(reverse=True)
print()
print(f"Largest production functions by CODE lines (top {TOP})")
print(f"  {'code':>5} {'total':>6} {'cmt%':>5}  function (file:line)")
for code, total, name, path, line in fns[:TOP]:
    cmt = 100 * (total - code) // max(total, 1)
    print(f"  {code:5d} {total:6d} {cmt:4d}%  {name}  ({path}:{line})")

print()
print("Note: `total` and `code` both exclude inline tests; `cmt%` includes blanks.")
print("A large `total` with a small `code` is documentation, not complexity.")
PY
