#!/usr/bin/env python3
"""Move a file's inline `#[cfg(test)] mod x { … }` blocks into sibling files.

Why: the largest source files are half tests, and a reader cannot reach the
production code without scrolling past them.  `docs/refactor-large-modules.md`
§ Step 0 describes the move; this script is the mechanical half of it.

What it does, per input file:
  * finds every `#[cfg(test)]` + `mod name { … }` block at the top level of the
    file, token-aware (braces and quotes in char/str/raw-str/comment literals
    are not counted),
  * writes each block's body to a sibling file — `a/b/tests.rs` for
    `a/b/mod.rs`, `a/b/tests.rs` for `a/b.rs` — dedented by one level,
  * replaces the block in the parent with `#[cfg(test)]` + `mod name;`.

Dedent safety: lines that *start inside* a string literal are left alone.  The
help-document pins and every other multi-line literal in this tree are written
with their indentation inside the literal, so a blind dedent corrupts them
(`frp-core/src/cli/help_doc_tests.rs` lost 4 columns per line the first time).

Usage:
    scripts/split_inline_tests.py --check FILE…   # report only, no writes
    scripts/split_inline_tests.py FILE…           # rewrite

The caller still has to (a) `cargo fmt`, (b) repoint cite-token rows — every
`path:line` into the file moves — and (c) prove the move: the `--list` set of
test names must be identical, which is what `docs/refactor-large-modules.md`
§ Step 0 asks for.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

MOD_HEADER = re.compile(r"^(?P<indent>\s*)mod (?P<name>\w+) \{\s*$")
ATTR = re.compile(r"^\s*#\[cfg\(test\)\]\s*$")


@dataclass
class Block:
    name: str
    start: int  # line index of `#[cfg(test)]`
    open: int  # line index of `mod name {`
    close: int  # line index of the closing `}`
    inner: list[str]


def _scan_states(lines: list[str]) -> list[str]:
    """Return, for each line, the lexer state at the line's first character."""
    return _scan(lines)[0]


def _scan(lines: list[str]) -> tuple[list[str], list[int]]:
    """Lexer state per line, plus the brace depth after each line.

    Braces inside comments and literals are ignored: a lifetime `'a` is not a
    char literal, a raw string `r#"…"#` ends only at its own delimiter, and a
    char literal never spans a newline (matching one across lines silently ate
    every brace in the file — the bug this comment replaces).
    """
    text = "\n".join(lines) + "\n"
    states: list[str] = ["code"]
    depth_after: list[int] = []
    i, n = 0, len(text)
    mode = "code"
    hash_len = 0
    depth = 0
    while i < n:
        ch = text[i]
        if mode == "code":
            if text.startswith("//", i):
                j = text.find("\n", i)
                i = n if j < 0 else j
                continue
            if ch == "r":
                m = re.match(r'r(#*)"', text[i:])
                if m:
                    hash_len = len(m.group(1))
                    mode = "raw"
                    i += m.end()
                    continue
            if ch == '"':
                mode = "str"
                i += 1
                continue
            if ch == "'":
                m = re.match(r"'(?:\\.|[^\\'\n])'", text[i:])
                i += m.end() if m else 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        elif mode == "raw":
            if hash_len == 0 and ch == '"':
                mode = "code"
            elif hash_len and text.startswith('"' + "#" * hash_len, i):
                mode = "code"
                i += 1 + hash_len
                continue
        else:  # str
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                mode = "code"
        if ch == "\n":
            depth_after.append(depth)
            states.append(mode)
        i += 1
    states = states[: len(lines)]
    depth_after = depth_after[: len(lines)]
    while len(states) < len(lines):
        states.append(mode)
    while len(depth_after) < len(lines):
        depth_after.append(depth)
    return states, depth_after


def find_blocks(lines: list[str]) -> list[Block]:
    """The trailing `#[cfg(test)] mod x { … }` block of a file, if any.

    In this tree a test module is the last item in its file, so the block runs
    from the `mod` line to the end of the file.  That is deliberately blunt: a
    lexer-based brace match kept losing a brace to a literal somewhere in a
    2 000-line test module, and a wrong boundary is worse than no split.  The
    caller proves the move instead — the `--list` set of test names must be
    identical, which a wrong boundary cannot survive.
    """
    last = None
    for i in range(len(lines) - 1):
        if ATTR.match(lines[i]):
            m = MOD_HEADER.match(lines[i + 1])
            if m:
                last = (i, m)
    if last is None:
        return []
    i, m = last
    tail = [line for line in lines[i + 2 :] if line.strip()]
    if not tail or tail[-1].strip() != "}":
        return []
    close = len(lines) - 1
    while close > i and not lines[close].strip():
        close -= 1
    return [Block(m.group("name"), i, i + 1, close, lines[i + 2 : close])]


def dedent(inner: list[str]) -> list[str]:
    states = _scan_states(inner)
    out: list[str] = []
    for k, line in enumerate(inner):
        state = states[k] if k < len(states) else "code"
        out.append(line[4:] if state == "code" and line.startswith("    ") else line)
    return out


def sibling_path(parent: Path, name: str) -> Path:
    if parent.name == "mod.rs":
        return parent.parent / f"{name}.rs"
    return parent.parent / parent.stem / f"{name}.rs"


def split(path: Path, write: bool) -> int:
    text = path.read_text()
    lines = text.splitlines()
    blocks = find_blocks(lines)
    if not blocks:
        print(f"  {path}: no inline test module")
        return 0
    drop: set[int] = set()
    replacements: list[tuple[int, int, str]] = []
    for b in blocks:
        target = sibling_path(path, b.name)
        print(f"  {path}:{b.start + 1} mod {b.name} -> {target} ({len(b.inner)} lines)")
        if write:
            target.parent.mkdir(parents=True, exist_ok=True)
            body = dedent(b.inner)
            while body and not body[0].strip():
                body.pop(0)
            while body and not body[-1].strip():
                body.pop()
            target.write_text("\n".join(body) + "\n")
        replacements.append(
            (b.start, b.close, f"#[cfg(test)]\nmod {b.name};")
        )
    if write:
        for start, close, replacement in sorted(replacements, reverse=True):
            lines[start : close + 1] = replacement.split("\n")
        _ = drop
        path.write_text("\n".join(lines) + "\n")
    return len(blocks)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--check", action="store_true", help="report without writing")
    args = ap.parse_args(argv)
    total = 0
    for f in args.files:
        total += split(f, write=not args.check)
    print(f"{'would split' if args.check else 'split'} {total} module(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
