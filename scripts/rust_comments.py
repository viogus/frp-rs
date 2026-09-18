"""Minimal Rust source scanner for the health gate.

`code_only(text)` removes `//` line comments and nested `/* */` block comments,
and blanks the **bodies** of string / char / raw literals (preserving newlines
so line numbers stay aligned). The result contains only code, so a source marker
cannot be satisfied by text that is not code: a comment mention, a
commented-out line, or a literal such as `'"'` / `r#"..."#`.

Understood literal forms:
  * `"..."` with backslash escapes, and `b"..."`
  * raw strings `r"..."`, `r#"..."#`, `br#"..."#` (any hash count)
  * char / byte-char literals `'x'`, `'\\n'`, `'\\''`, `b'x'`, incl. `\\xNN`
    and `\\u{...}`
  * lifetimes (`'a`) are left as code, not mistaken for a char literal

Limits — this is a comment remover, not a compiler front end: raw identifiers
(`r#name`), macro token trees, and exotic literal forms are not modelled, and a
`\\xNN` / `\\u{...}` escape is consumed approximately. The health gate's checks
each state their own textual-presence limits separately; this module only makes
"is this marker inside a comment/literal" reliable for real Rust source.
"""
import re


def code_only(text):
    out = []
    i, n = 0, len(text)

    def emit(s):
        out.append(''.join('\n' if ch == '\n' else ' ' for ch in s))

    while i < n:
        c = text[i]
        if text.startswith('//', i):
            j = text.find('\n', i)
            i = n if j < 0 else j
            continue
        if text.startswith('/*', i):
            depth, i = 1, i + 2
            while i < n and depth:
                if text.startswith('/*', i):
                    depth += 1
                    i += 2
                elif text.startswith('*/', i):
                    depth -= 1
                    i += 2
                elif text[i] == '\n':
                    out.append('\n')
                    i += 1
                else:
                    i += 1
            continue
        # raw / byte-raw string: r"..", r#".."#, br#".."# — not a raw identifier
        if c in 'rb' and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == '_')):
            m = re.match(r'b?r(#*)"', text[i:])
            if m:
                term = '"' + m.group(1)
                start = i + m.end()
                j = text.find(term, start)
                end = n if j < 0 else j + len(term)
                emit(text[i:end])
                i = end
                continue
        # normal / byte string
        if c == '"' or text.startswith('b"', i):
            k = i + (2 if text.startswith('b"', i) else 1)
            while k < n:
                if text[k] == '\\':
                    k += 2
                    continue
                if text[k] == '"':
                    k += 1
                    break
                k += 1
            emit(text[i:k])
            i = k
            continue
        # char / byte-char literal, else a lifetime
        if c == "'" or text.startswith("b'", i):
            k = i + (2 if text.startswith("b'", i) else 1)
            if k < n and text[k] == '\\':
                k += 1
                if k < n and text[k] == 'x':
                    k += 3
                elif k < n and text[k] == 'u' and k + 1 < n and text[k + 1] == '{':
                    j = text.find('}', k + 2)
                    k = n if j < 0 else j + 1
                else:
                    k += 1
                if k < n and text[k] == "'":
                    k += 1
                emit(text[i:k])
                i = k
                continue
            if k + 1 < n and text[k] != "'" and text[k + 1] == "'":
                emit(text[i:k + 2])
                i = k + 2
                continue
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return ''.join(out)
