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
#   1. per-file lines: total / test / production, where "test" covers an inline
#      test region — `#[cfg(test)]` or `#[cfg(all(test, …))]`, ending at the
#      item the attribute decorates — a whole-file test module (`tests.rs`,
#      `*_tests.rs`, `*_test.rs`, anything under a `tests/` directory) and a
#      `#[cfg(test)] mod X;` sibling — the file-ification the refactor plan is
#      built on
#   2. the largest production functions, measured in CODE lines (comments and
#      blanks excluded)
#
# Usage:
#   bash scripts/large-functions.sh            # default: top 12 functions
#   bash scripts/large-functions.sh --top 25
#   bash scripts/large-functions.sh --all      # every file, not just the top 14
#
# Read-only; never fails the build. See docs/refactor-large-modules.md.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

TOP=12
ALL=0
case "${1:-}" in
  --top) TOP="${2:-12}" ;;
  --all) ALL=1 ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found — cannot measure"
  exit 0
fi

python3 - "$TOP" "$ALL" <<'PY'
import os
import re
import sys

TOP = int(sys.argv[1])
ALL = sys.argv[2] == '1'
ROOTS = ('frp-core/src', 'frp-server/src', 'frp-client/src', 'frp-vnet/src')
FN = re.compile(r'^(\s*)(?:pub(?:\([^)]*\))?\s+)?(?:const\s+|async\s+|unsafe\s+)*fn\s+([A-Za-z0-9_]+)')
# A test gate is an attribute whose `cfg` predicate can hold only where `test`
# is set: `#[cfg(test)]`, or `#[cfg(all(…, test, …))]` — 13 in-tree sites, 10
# of them decorating an inline `mod {` and 3 writing
# `all(feature = "vnet", test)` over a `use`. The base script knew only
# `#[cfg(test)]` and scored those regions as production. The predicate is
# parsed, not pattern-matched, so the negated spellings — `all(not(test), …)`,
# `all(not (test), …)`, `all(not(any(test, …)))` — are rejected: they compile
# where `test` is *off*.
#
# The predicate is read by depth counting (`cfg_attribute`), not by a greedy
# `(.*)`, and the attribute may be followed on its line by further attributes,
# comments or the item it decorates (`gate_tail_ok`): `#[cfg(test)] /* why */`,
# `#[cfg(test)] // see (a)]` and
# `#[cfg(test)] #[path = "declared_helper.rs"] mod declared;` are all gates.
#
# NOTE: the opening `#[cfg(` must still close on the same line, so the wrapped
# spelling `#[cfg(all(` / `test,` / `feature = "x"` / `))]` is not recognised.
# No in-tree file writes one; it is filed as residue rather than special-cased.
CFG_OPEN = re.compile(r'\s*#\s*\[\s*cfg\s*\(')
# `r"…"`, `r#"…"#`, `r##"…"##`, `br#"…"#`: the `#`s set the terminator count,
# and the literal may span lines.
RAW_OPEN = re.compile(r'(?:b?r|cr)(#*)"')
ATTR_LINE = re.compile(r'\s*#\[')
MOD_DECL = re.compile(r'\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;')
PATH_ATTR = re.compile(r'\s*#\[path\s*=\s*"([^"]+)"\s*\]')
# `tests.rs`, `test.rs`, `key_tests.rs`, `single_test.rs` — the whole file is a
# test module by convention, so it has nothing to score as production. The rule
# is deliberately name-only: without resolving the declaring `mod` the script
# cannot tell, so a production module that happens to carry one of these names
# would be misread as test (no in-tree instance).
TEST_FILE = re.compile(r'(?:^|_)tests?\.rs$')


def item_end(lines, start):
    """(last index, kind, closed) for the item that begins at `start`.

    The item is the thing an attribute decorates, and its first top-level
    terminator decides how far it runs: a `;` ends a `use` / `const` /
    `static` / expression statement (and an out-of-line `mod X;`
    declaration), a `{` opens a body that is brace-matched to its closing
    line. That is how a `#[cfg(test)]` region ends at its own item instead
    of at the next `mod` in the file.

    Braces and semicolons inside `//`, `/* */`, string literals, char
    literals, lifetimes and raw strings do not count: this is the same
    skipper `fn_body_end` has always used, lifted out so the region walk
    uses it too. A naive counter closed an inline test region at the first `{` or
    `}` inside a literal — `frp-core/src/logging.rs` lost 48 production
    lines to one. Parentheses and brackets are tracked until the body
    opens, so the `;` in a `[&str; 2]` type does not end a `const` early.

    Raw strings are skipped by terminator count, not by quote parity, and
    may span lines: `r"…"` ends at the next `"`, `r#"…"#` at the next `"#`.
    Scanning one as code costs `frp-core/src/v2_handshake.rs` 568 production
    lines and `frp-core/src/msg.rs` 148 — both literals sit inside a
    `#[cfg(test)]` region, and their braces then close it early. Ordinary
    strings stay line-local (a backslash before the newline is a continuation).

    `closed` is False only when a `{` opened and never returned to depth
    zero; the caller decides what an unterminated body means.
    """
    paren, depth, seen_open = 0, 0, False
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
            if c in 'brc':
                m = RAW_OPEN.match(line, j)
                if m:
                    # Raw string: no escapes, and it may span lines. It ends
                    # at the first `"` followed by exactly this many `#`.
                    term = '"' + '#' * len(m.group(1))
                    j = m.end()
                    while i < n:
                        line = lines[i]
                        p = line.find(term, j)
                        if p >= 0:
                            j = p + len(term)
                            break
                        i += 1
                        j = 0
                    if i >= n:
                        break
                    continue
            if c == '"':
                j += 1
                while j < len(line):
                    if line[j] == '"':
                        j += 1
                        break
                    if line[j] == '\\':
                        if j + 1 == len(line):
                            # A backslash immediately before the newline
                            # continues the literal on the next physical line,
                            # so braces there are string content, not code.
                            i += 1
                            if i >= n:
                                break
                            line = lines[i]
                            j = 0
                            continue
                        j += 2
                        continue
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
            if not seen_open:
                if c in '([':
                    paren += 1
                elif c in ')]':
                    paren -= 1
                elif c == ';' and paren <= 0:
                    return i, 'stmt', True
            if c == '{':
                depth += 1
                seen_open = True
            elif c == '}':
                depth -= 1
                if seen_open and depth == 0:
                    return i, 'brace', True
            j += 1
        i += 1
    return i - 1, 'brace', False


def cfg_args(inner):
    """Split a `cfg` predicate's argument list on its own top-level commas.

    Nesting and quoted values are respected, so `all(test, feature = "a,b")`
    is two arguments and the comma inside the string does not split it.
    """
    out, cur, depth, quote = [], [], 0, None
    for ch in inner:
        if quote is not None:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in '"\'':
            quote = ch
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif ch == ',' and depth == 0:
            out.append(''.join(cur))
            cur = []
            continue
        cur.append(ch)
    out.append(''.join(cur))
    return [a.strip() for a in out if a.strip()]


def cfg_implies_test(pred):
    """Does `cfg(pred)` hold only where `test` is set?

    A bare `test` does. `all(a, …)` does when any argument does — the
    conjunction cannot hold without it. `any(a, …)` does only when every
    argument does. `not(…)` never does, which is what rejects
    `all(not(test), …)`, `all(not (test), …)` and `all(not(any(test, …)))`:
    those compile where `test` is *off*.
    """
    pred = pred.strip()
    m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', pred)
    if not m or not pred.endswith(')'):
        return pred == 'test'
    args = cfg_args(pred[m.end():-1])
    if m.group(1) == 'all':
        return any(cfg_implies_test(a) for a in args)
    if m.group(1) == 'any':
        return bool(args) and all(cfg_implies_test(a) for a in args)
    return False


def _skip_comment(line, i):
    """Index just past the comment at `i`; `len(line)` when it runs to EOL."""
    if line.startswith('//', i):
        return len(line)
    end = line.find('*/', i + 2)
    return len(line) if end < 0 else end + 2


def _skip_string(line, i):
    """Index just past the `"…"` that opens at `i` (escape-aware)."""
    i, n = i + 1, len(line)
    while i < n:
        if line[i] == '\\':
            i += 2
            continue
        if line[i] == '"':
            return i + 1
        i += 1
    return n


def _skip_char(line, i):
    """Index after the char literal at `i`; a lifetime advances one char."""
    n = len(line)
    if i + 2 < n and line[i + 1] == '\\':
        return i + 3                        # '\n'-style escape
    if i + 2 < n and line[i + 2] == "'":
        return i + 3                        # 'x'-style literal
    return i + 1                            # lifetime — ordinary code


def closing_bracket(line, i):
    """Index of the `]` matching the `[` at `i`, or -1.

    Depth-counted and literal-aware, so a bracket inside a string, a char
    literal or a comment cannot close it early. The greedy `(.*)` could not do
    this: `#[cfg(test)] // see (a)]` parsed as a malformed predicate and the
    line stopped being a gate.
    """
    depth, n = 0, len(line)
    while i < n:
        if line.startswith('/*', i) or line.startswith('//', i):
            i = _skip_comment(line, i)
            continue
        c = line[i]
        if c == '"':
            i = _skip_string(line, i)
            continue
        if c == "'":
            i = _skip_char(line, i)
            continue
        if c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def cfg_attribute(line):
    """(`predicate`, index just past the attribute) for a leading `#[cfg(…)`].

    `(None, -1)` when the line does not open a well-formed one. The closing
    `)` is found by depth counting, so a `)` or `]` inside a string or a
    trailing comment cannot end the predicate early, and the attribute's `]`
    must follow it (`#[cfg(test) ]` is accepted; one split across lines is not
    — see the note above `CFG_OPEN`).
    """
    m = CFG_OPEN.match(line)
    if not m:
        return None, -1
    start, n, depth, i = m.end(), len(line), 1, m.end()
    while i < n:
        if line.startswith('/*', i) or line.startswith('//', i):
            i = _skip_comment(line, i)
            continue
        c = line[i]
        if c == '"':
            i = _skip_string(line, i)
            continue
        if c == "'":
            i = _skip_char(line, i)
            continue
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                j = i + 1
                while j < n and line[j] in ' \t\r':
                    j += 1
                if j >= n or line[j] != ']':
                    return None, -1
                # A block comment inside the predicate survives the scan but
                # not the argument split, so drop it before parsing.
                return re.sub(r'/\*.*?\*/', '', line[start:i]), j + 1
        i += 1
    return None, -1


def item_tail_ok(line, i):
    """Is `line[i:]` — the decorated item sharing the gate's line — sound?

    Anything is accepted except an unbalanced bracket: a `)` or `]` with
    nothing to match it means the `)]` above was not the attribute's, which is
    the one way a mistyped gate can still look well formed.
    """
    depth, n = 0, len(line)
    while i < n:
        if line.startswith('/*', i) or line.startswith('//', i):
            i = _skip_comment(line, i)
            continue
        c = line[i]
        if c == '"':
            i = _skip_string(line, i)
            continue
        if c == "'":
            i = _skip_char(line, i)
            continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
            if depth < 0:
                return False
        i += 1
    return True


def gate_tail_ok(line, i):
    """Is `line[i:]` a legal tail for a `#[cfg(…)]` attribute?

    Whitespace, `//` and `/* */` comments and further `#[…]` attributes are —
    `#[cfg(test)] /* why */`, `#[cfg(test)] // see (a)]` and
    `#[cfg(test)] #[allow(dead_code)]` are all gates. So is the item the
    attribute decorates when it shares the line, which is what makes
    `#[cfg(test)] #[path = "declared_helper.rs"] mod declared;` a gate on an
    out-of-line test module.
    """
    n = len(line)
    while i < n:
        c = line[i]
        if c in ' \t\r':
            i += 1
        elif line.startswith('/*', i) or line.startswith('//', i):
            i = _skip_comment(line, i)
        elif c == '#' and i + 1 < n and line[i + 1] == '[':
            j = closing_bracket(line, i + 1)
            if j < 0:
                return False
            i = j + 1
        else:
            return item_tail_ok(line, i)
    return True


def is_test_gate(line):
    """Is this line a `#[cfg(…)]` that compiles only where `test` is set?"""
    pred, end = cfg_attribute(line)
    if pred is None:
        return False
    return gate_tail_ok(line, end) and cfg_implies_test(pred)


def attribute_run(lines, start):
    """(item line, item column, `#[path]` value) after the run at `start`.

    The run is consumed one attribute at a time rather than one line at a
    time, because attributes may share a line with each other and with the item
    they decorate: `#[cfg(test)] #[path = "declared_helper.rs"] mod declared;`
    declares an out-of-line test module, and a line-at-a-time walk looked for
    the declaration on the *next* line and charged the production code below it
    to tests. `path_attr` is the last `#[path]` of the run, or None.
    """
    i, n, path_attr = start, len(lines), None
    while True:
        line = lines[i]
        k = 0
        while True:
            while k < len(line) and line[k] in ' \t\r':
                k += 1
            if line.startswith('/*', k) or line.startswith('//', k):
                k = _skip_comment(line, k)
                continue
            if not line.startswith('#[', k):
                break
            end = closing_bracket(line, k + 1)
            if end < 0:                     # malformed — stop at the item
                return i, k, path_attr
            m = PATH_ATTR.search(line[k:end + 1])
            if m:
                path_attr = m.group(1)
            k = end + 1
        if k < len(line):
            return i, k, path_attr
        if i + 1 < n and ATTR_LINE.match(lines[i + 1]):
            i += 1
            continue
        return i + 1, 0, path_attr


def test_blocks(lines):
    """(`#[cfg(test)]` regions, out-of-line test-module declarations).

    The first element is a list of (start, end) index pairs covering each
    test region: the attribute lines plus the item they decorate. The second
    is a list of (module name, `#[path]` value or None) for each `mod X;`
    declaration whose body lives in a sibling file; those regions cover only
    the attribute and the declaration line.

    A region ends at the item the attribute decorates, not at the next `mod`
    in the file. Scanning forward for a `mod` charged everything between the
    attribute and that module to tests: `frp-core/src/bridge.rs` carries
    `#[cfg(test)]` above a single `use` at line 5 while its `mod tests` is at
    line 1085, so the file read 4 production lines. `use` / `const` /
    `static` (and any other statement) end at their `;`; anything that opens
    a body — `mod` / `fn` / `impl` / `thread_local!` — is brace-matched with
    `item_end`'s literal-aware scan.

    Any `#[cfg(…)]` that compiles only where `test` is set counts:
    `#[cfg(test)]` and `#[cfg(all(…, test, …))]` (`is_test_gate` parses the
    predicate, so the negated spellings do not). A `#[path]` may sit above or
    below the gate: attributes stack on one item, so the whole attribute run is
    part of the region and is searched for `#[path]` — even when the run, the
    `#[path]` and the `mod X;` declaration all share one line.

    An out-of-line declaration must not be brace-matched: `mod tests;` has no
    body, so scanning forward for the next `{` charges the production code that
    follows it to the test module. That is what made `ssh_gateway.rs` read 2726
    production / 24 test once its tests moved out (`2742` / `8` is the truth) —
    16 production lines swallowed by the first braced statement after the
    `mod tests;` this file had always carried.
    """
    blocks, out_of_line = [], []
    i, n = 0, len(lines)
    while i < n:
        if not is_test_gate(lines[i]):
            i += 1
            continue
        start = i
        while start > 0 and ATTR_LINE.match(lines[start - 1]):
            start -= 1
        j, col, path_attr = attribute_run(lines, start)
        if j >= n:
            break
        decl = MOD_DECL.match(lines[j], col)
        if decl:
            blocks.append((start, j))
            out_of_line.append((decl.group(1), path_attr))
            i = j + 1
            continue
        end, _kind, closed = item_end(lines, j)
        if not closed:
            end = n - 1     # unterminated body — charge the rest of the file
        blocks.append((start, end))
        i = end + 1
    return blocks, out_of_line


def is_test(idx, blocks):
    return any(a <= idx <= b for a, b in blocks)


def fn_body_end(lines, start):
    """Index just past the `}` that closes the fn starting at `start`.

    Measuring a function as "distance to the next `fn`" is wrong: type and const
    definitions between two functions get charged to the first one. That reported
    `health_check_monitored` (really 3 lines) as 434, and a nested 19-line
    `record_plugin` as 212. Brace-matching the body is the honest measure.

    Skips `//`, `/* */`, and string/char literals so braces inside them do not
    count — `item_end` is that scanner. Returns None if the body never closes.
    """
    end, _kind, closed = item_end(lines, start)
    if not closed:
        return None
    return end + 1


def is_test_file(path):
    """Is this whole file a test module?

    A whole-file test module (`config/tests.rs`) carries no `#[cfg(test)]`
    inside it — the attribute is on the `mod` that includes it — so excluding
    by attribute alone miscounts it as production. 6005 "production" lines
    turned out to be a test file. The exact-name check (`tests.rs`, or
    anything under a `tests/` directory) missed the siblings the file-ification
    train creates: `key_tests.rs`, `virtual_ctrl_tests.rs`, `preauth_tests.rs`
    and `unregister_generation_tests.rs` were all scored as production.
    """
    name = os.path.basename(path)
    return bool(TEST_FILE.search(name)
                or ('%stests%s' % (os.sep, os.sep)) in os.path.dirname(path) + os.sep)


def sibling_paths(path, name, path_attr):
    """Where Rust looks for an out-of-line `mod name;` declared in `path`.

    Rust resolves `mod X;` inside `parent.rs` under a `parent/` directory —
    `parent/X.rs` or `parent/X/mod.rs` — and never beside it; only a
    `mod.rs` / `lib.rs` / `main.rs` parent resolves `X.rs` / `X/mod.rs` in its
    own directory. Offering `dir/X.rs` for a `parent.rs` would mark an unrelated
    production module as test. `#[path = "…"]` overrides all of it.
    """
    d = os.path.dirname(path)
    out = []
    if path_attr:
        out.append(os.path.join(d, path_attr))
    stem = os.path.basename(path)[:-3]        # drop the `.rs`
    if stem in ('mod', 'lib', 'main'):
        out.append(os.path.join(d, name + '.rs'))
        out.append(os.path.join(d, name, 'mod.rs'))
    else:
        out.append(os.path.join(d, stem, name + '.rs'))
        out.append(os.path.join(d, stem, name, 'mod.rs'))
    return out


sources = {}
for root in ROOTS:
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            if not name.endswith('.rs'):
                continue
            path = os.path.join(dirpath, name)
            try:
                sources[path] = open(path, encoding='utf8', errors='ignore').read().split('\n')
            except OSError:
                continue

spans = {path: test_blocks(lines) for path, lines in sources.items()}

# A test module that is not an inline `#[cfg(test)] mod { … }`: either the file
# is named as one, or some `#[cfg(test)] mod X;` declaration pulls it in.
test_files = {path for path in sources if is_test_file(path)}
for path in sources:
    for name, path_attr in spans[path][1]:
        for cand in sibling_paths(path, name, path_attr):
            if cand in sources:
                test_files.add(cand)

per_file = []
fns = []
for path in sorted(sources):
    lines = sources[path]
    total = len(lines)
    if path in test_files:
        per_file.append((0, total, total, path))
        continue
    blocks = spans[path][0]
    prod_idx = [i for i in range(total) if not is_test(i, blocks)]
    prod = len(prod_idx)
    per_file.append((prod, total, total - prod, path))

    starts = [(m.group(2), i) for i in prod_idx
              for m in [FN.match(lines[i])] if m]
    for name, st in starts:
        end = fn_body_end(lines, st)          # brace-matched, see below
        # Test the body's LAST line, not `end`: `end` is the index just past the
        # closing brace, so when a `#[cfg(test)] mod` starts on the very next
        # line an inclusive test on `end` silently drops the function. That hid
        # `frp-server/src/control/login.rs::authenticate` (492 code lines, the 5th largest in the repo).
        if end is None or is_test(end - 1, blocks):
            continue
        seg = lines[st:end]
        code = sum(1 for l in seg if l.strip() and not l.strip().startswith('//'))
        fns.append((code, end - st, name, path, st + 1))

per_file.sort(reverse=True)
print("Per-file lines (test modules excluded)")
print(f"  {'production':>10} {'total':>8} {'test':>8}  file")
for prod, total, test, path in per_file[:len(per_file) if ALL else 14]:
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
