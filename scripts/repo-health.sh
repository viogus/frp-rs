#!/usr/bin/env bash
# repo-health.sh — regenerate the numbers quoted in CLAUDE.md's "Current Health".
#
# Why this exists: those figures (unsafe-block counts, test counts, binary sizes)
# were hand-maintained in prose and had silently drifted — e.g. the table claimed
# 17 unsafe blocks in frp-core while the tree had 21. Anything that can be counted
# should be counted by a script, not typed into a document.
#
# Usage:
#   bash scripts/repo-health.sh           # fast checks (no build)
#   bash scripts/repo-health.sh --sizes   # also build release binaries and measure
#
# Exit code: 0 if the mandatory invariants hold, 1 otherwise. The version check
# is a real gate (see "Versioning (mandatory)" in CLAUDE.md); the rest is report.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0
hr() { printf '%s\n' "------------------------------------------------------------"; }
hdr() { hr; printf '%s\n' "$1"; hr; }

# ---------------------------------------------------------------- versioning
hdr "Version alignment (mandatory — CLAUDE.md)"

# The canonical version is frp-core's Cargo.toml.
canon=$(grep -m1 '^version' frp-core/Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
printf '  canonical (frp-core/Cargo.toml) : %s\n' "$canon"

check_ver() { # <label> <actual>
  if [ "$2" = "$canon" ]; then
    printf '  ok    %-34s %s\n' "$1" "$2"
  else
    printf '  FAIL  %-34s %s (expected %s)\n' "$1" "$2" "$canon"
    fail=1
  fi
}

for c in frp-core frp-server frp-client frps frpc; do
  check_ver "$c/Cargo.toml" "$(grep -m1 '^version' "$c/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"
done
check_ver "frp-core/src/lib.rs VERSION" \
  "$(grep -m1 'pub const VERSION' frp-core/src/lib.rs | sed -E 's/.*"([^"]+)".*/\1/')"
# `VERSION="${1:-0.71.0}"` — pull the default out of the parameter expansion.
check_ver "scripts/download-frp-rs.sh" \
  "$(grep -m1 -oE 'VERSION="\$\{[0-9]+:-v?[0-9]+\.[0-9]+\.[0-9]+\}"' scripts/download-frp-rs.sh \
     | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
check_ver "README.md version" \
  "$(grep -oE 'frp-rs [0-9]+\.[0-9]+\.[0-9]+' README.md | head -1 | sed 's/frp-rs //')"

# frp-vnet is deliberately NOT aligned (CLAUDE.md documents this exception).
vnet=$(grep -m1 '^version' frp-vnet/Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
printf '  info  %-34s %s (exception, not aligned)\n' "frp-vnet/Cargo.toml" "$vnet"

# ---------------------------------------------------------------- code size
hdr "Code size"
printf '  %-14s %8s %8s\n' "crate" "files" "lines"
for c in frp-core frp-server frp-client frp-vnet frps frpc; do
  [ -d "$c/src" ] || continue
  files=$(find "$c/src" -name '*.rs' | wc -l | tr -d ' ')
  lines=$(find "$c/src" -name '*.rs' -print0 | xargs -0 cat 2>/dev/null | wc -l | tr -d ' ')
  printf '  %-14s %8s %8s\n' "$c" "$files" "$lines"
done

# ---------------------------------------------------------------- tests
hdr "Tests"
printf '  test functions      : %s\n' \
  "$(grep -rhoE '#\[(tokio::)?test\]' --include=*.rs frp-core frp-server frp-client frp-vnet frps frpc | wc -l | tr -d ' ')"
printf '  files with tests    : %s\n' \
  "$(grep -rlE '#\[(tokio::)?test\]' --include=*.rs frp-core frp-server frp-client frp-vnet frps frpc | wc -l | tr -d ' ')"
printf '  proptest blocks     : %s\n' \
  "$(grep -rho 'proptest!' --include=*.rs frp-core frp-server frp-client frp-vnet | wc -l | tr -d ' ')"
printf '  integration test dirs: %s\n' \
  "$(find . -path ./target -prune -o -type d -name tests -print 2>/dev/null | grep -vc '^\./\.' || true)"
printf '\n  NOTE: the number of tests that *pass* is a runtime fact, not a static one.\n'
printf '  Run: cargo test --workspace --all-features\n'

# ---------------------------------------------------------------- unsafe
hdr "Unsafe usage"
printf '  %-12s %8s %10s %12s %10s\n' "crate" "blocks" "unsafe fn" "unsafe impl" "SAFETY cmts"
for c in frp-core frp-server frp-client frp-vnet; do
  [ -d "$c/src" ] || continue
  b=$(grep -rho 'unsafe *{' --include=*.rs "$c/src" | wc -l | tr -d ' ')
  f=$(grep -rho 'unsafe fn' --include=*.rs "$c/src" | wc -l | tr -d ' ')
  i=$(grep -rho 'unsafe impl' --include=*.rs "$c/src" | wc -l | tr -d ' ')
  s=$(grep -rho '// SAFETY' --include=*.rs "$c/src" | wc -l | tr -d ' ')
  printf '  %-12s %8s %10s %12s %10s\n' "$c" "$b" "$f" "$i" "$s"
done
printf '\n  Convention: every unsafe block carries a `// SAFETY:` comment.\n'

# Gate: an `unsafe {` block with no `// SAFETY:` justification. The convention was
# previously enforced by review alone.
#
# Getting this right matters more than it looks. A first attempt used a fixed
# 3-line look-behind and reported 14 violations on a clean tree — every one a
# false positive, because the justification is usually a multi-line comment block
# (4-9 lines) or sits inside the block. So: walk up over the whole contiguous
# comment/attribute block, and also look a few lines into the block itself.
if command -v python3 >/dev/null 2>&1; then
  unsafe_misses=$(python3 - <<'PY'
import os, re

INNER = 4  # lines into the block to also scan (catches `let n = unsafe {` + comment inside)
MARKER = re.compile(r'//\s*SAFETY')


def justified(lines, i):
    seen = []
    j = i - 1
    while j >= 0:  # contiguous comment / attribute block immediately above
        s = lines[j].strip()
        if s.startswith('//') or s.startswith('#['):
            seen.append(s)
            j -= 1
            continue
        break
    seen.extend(l.strip() for l in lines[i:i + INNER])
    return any(MARKER.search(s) for s in seen)


for crate in ('frp-core', 'frp-server', 'frp-client', 'frp-vnet'):
    src = os.path.join(crate, 'src')
    if not os.path.isdir(src):
        continue
    for root, _dirs, files in os.walk(src):
        for fn in files:
            if not fn.endswith('.rs'):
                continue
            path = os.path.join(root, fn)
            try:
                lines = open(path, encoding='utf8', errors='ignore').read().split('\n')
            except OSError:
                continue
            for i, line in enumerate(lines):
                if re.search(r'unsafe\s*\{', line) and not justified(lines, i):
                    print('%s:%d' % (path, i + 1))
PY
)
  if [ -n "$unsafe_misses" ]; then
    printf '%s\n' "$unsafe_misses" | sed 's/^/    /'
    n=$(printf '%s\n' "$unsafe_misses" | wc -l | tr -d ' ')
    printf '  FAIL  %s unsafe block(s) with no `// SAFETY:` justification\n' "$n"
    fail=1
  else
    printf '  ok    every unsafe block has a `// SAFETY:` justification\n'
  fi
else
  printf '  skip  python3 not found — unsafe/SAFETY gate not evaluated\n'
fi

# ---------------------------------------------------------------- vendored
hdr "Vendored crates ([patch.crates-io])"
for v in vendor/*/; do
  n=$(basename "$v")
  [ -f "$v/Cargo.toml" ] || continue
  ver=$(grep -m1 '^version' "$v/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')
  readme="MISSING"
  [ -f "$v/README-FRP-RS.md" ] && readme="ok"
  printf '  %-10s %-10s README-FRP-RS.md: %s\n' "$n" "$ver" "$readme"
  [ "$readme" = "MISSING" ] && fail=1
done
printf '\n  Each vendored crate must document WHY and its EXIT CONDITION.\n'
printf '  A vendored copy pins the crate: track upstream advisories by hand.\n'

# ---------------------------------------------------------------- docs
hdr "Docs"

if command -v python3 >/dev/null 2>&1; then
  # (a) Gate: every doc is reachable from the index. A doc nobody links to is a
  # doc nobody reads, and the index is edited by hand, so it drifts.
  index_misses=$(python3 - <<'PY'
import os

INDEX = os.path.join('docs', 'README.md')
try:
    index = open(INDEX, encoding='utf8').read()
except OSError:
    print('docs/README.md is missing')
    raise SystemExit
for name in sorted(os.listdir('docs')):
    if name == 'README.md':
        continue
    path = os.path.join('docs', name)
    if os.path.isfile(path) and name.endswith('.md'):
        if name not in index:
            print('docs/%s' % name)
    elif os.path.isdir(path) and name not in index:
        print('docs/%s/' % name)
PY
)
  if [ -n "$index_misses" ]; then
    printf '%s\n' "$index_misses" | sed 's/^/    not in docs\/README.md: /'
    n=$(printf '%s\n' "$index_misses" | wc -l | tr -d ' ')
    printf '  FAIL  %s doc(s)/dir(s) unreachable from the index\n' "$n"
    fail=1
  else
    printf '  ok    every docs/*.md and docs/*/ is reachable from docs/README.md\n'
  fi

  # (b) Report: paths inside docs/archive/** still say `docs/superpowers/...`,
  # deliberately (historical records are not rewritten). Verify the documented
  # translation still holds, so the claim in docs/archive/README.md stays true.
  archive=$(python3 - <<'PY'
import os, re

pat = re.compile(r'docs/superpowers/([A-Za-z0-9_./-]+)')
total = resolved = 0
for root, _dirs, files in os.walk(os.path.join('docs', 'archive')):
    for fn in files:
        if not fn.endswith(('.md', '.json')):
            continue
        p = os.path.join(root, fn)
        for line in open(p, encoding='utf8', errors='ignore'):
            for m in pat.finditer(line):
                total += 1
                rel = m.group(1).rstrip('.,;:)`')
                if os.path.exists(os.path.join('docs', 'archive', rel)):
                    resolved += 1
print('%d %d' % (total, resolved))
PY
)
  set -- $archive
  printf '  info  archive path refs: %s, resolvable via the docs/archive/ prefix: %s\n' "${1:-0}" "${2:-0}"
  printf '        (the remainder point at specs that were never written — pre-existing)\n'

  # (c) Gate: a path a doc or source comment names must still open. The naive
  # sweep that produced 135 hits in TODO.md failed because it resolved every
  # path from the repo root and could not tell `frp-core/tls` (a Cargo feature)
  # from a path. This one is precise because it (i) only checks spans anchored
  # at a known repo root, (ii) tries the *referencing file's* directory first
  # and the repo root second, and (iii) models `[features]` plus implicit
  # features from optional dependencies instead of carrying an exclusion list.
  # Locator-less spans (`mux.rs`, `control/mod.rs`) have no recoverable base and
  # are counted, not checked — they are the naive sweep's false positives.
  # Point-in-time documents (history, dated audits, changelog, the refactor
  # proposal, and the backlog that quotes removed paths as evidence) describe an
  # older tree on purpose and are out of scope; the archive has check (b).
  paths=$(python3 - <<'PY'
import os, re

ROOTS = ('src/', 'tests/', 'benches/', 'examples/',
         'docs/', 'scripts/', 'vendor/', 'docker/', '.github/',
         'frp-core/', 'frp-server/', 'frp-client/', 'frp-vnet/', 'frps/', 'frpc/')
MANIFEST = re.compile(r'^(Cargo\.toml|Cargo\.lock)$')
EXTS = ('.rs', '.toml', '.md', '.sh', '.yml', '.yaml', '.json', '.lock')
SKIP_DIRS = ('docs/archive/', 'docs/history/', 'docs/audit/')
SKIP_FILES = ('CHANGELOG.md', 'TODO.md', 'performance-audit.md',
              'docs/refactor-large-modules.md')
BANNED = ' \t{}*<>|'

def cargo_features(crate):
    path = os.path.join(crate, 'Cargo.toml')
    if not os.path.isfile(path):
        return None
    feats, section = set(), ''
    for line in open(path, encoding='utf8', errors='ignore'):
        line = line.strip()
        if line.startswith('['):
            section = line.strip('[]').strip()
            continue
        m = re.match(r'([A-Za-z0-9_-]+)\s*=', line)
        if not m:
            continue
        if section == 'features':
            feats.add(m.group(1))
        elif 'dependencies' in section and re.search(r'optional\s*=\s*true', line):
            feats.add(m.group(1))     # implicit feature of an optional dependency
    return feats

SPAN = re.compile(r'`([^`\n]+)`')

def normalize(span):
    s = span.strip()
    if not s or '...' in s or any(c in s for c in BANNED) or s[0] in '/~$':
        return None
    s = re.sub(r'::[A-Za-z_][A-Za-z0-9_:]*$', '', s)           # file.rs::symbol
    s = re.sub(r'#[A-Za-z0-9_.-]+$', '', s)                    # file.md#anchor
    s = re.sub(r':~?\d+([-\u2013]\d+)?([/,]\d+)*\+?$', '', s)  # file.rs:12-20,30
    return s or None

def classify(span, base):
    p = normalize(span)
    if p is None:
        return 'ignore'
    if p.startswith('docs/superpowers'):
        return 'superpowers'      # documented old name of docs/archive/
    has_slash = '/' in p.rstrip('/')
    manifest = bool(MANIFEST.match(os.path.basename(p.rstrip('/'))))
    if not has_slash and not manifest:
        return 'bare' if os.path.splitext(p)[1] in EXTS else 'ignore'
    if not (p.startswith(ROOTS) or manifest):
        return 'shorthand' if os.path.splitext(p)[1] in EXTS else 'ignore'
    if has_slash:             # `crate/feature` (or `dir/crate/feature`) is not a path
        left, right = p.rsplit('/', 1)
        feats = cargo_features(left)
        if feats is not None and right in feats:
            return 'feature'
    for cand in (os.path.normpath(os.path.join(base, p)), os.path.normpath(p)):
        if os.path.exists(cand):
            return 'ok'
    return 'stale'

def spans(lines):
    for lineno, line in lines:
        for m in SPAN.finditer(line):
            yield lineno, m.group(1)

def md(path):
    return enumerate(open(path, encoding='utf8', errors='ignore'), 1)

def rs(path):
    return [(i, l) for i, l in enumerate(open(path, encoding='utf8', errors='ignore'), 1)
            if l.lstrip().startswith(('//', '/*', '*'))]

counts = {k: 0 for k in ('ok', 'stale', 'feature', 'shorthand', 'bare',
                         'superpowers', 'ignore')}
hits = []
for root, dirs, files in os.walk('.'):
    dirs[:] = [d for d in dirs if d not in ('.git', 'target')]
    for fn in sorted(files):
        p = os.path.join(root, fn)[2:]
        is_md, is_rs = fn.endswith('.md'), fn.endswith('.rs')
        if not (is_md or is_rs):
            continue
        if is_md and (p.startswith(SKIP_DIRS) or p in SKIP_FILES):
            continue
        if is_rs and p.startswith('vendor/'):   # third-party source, pinned
            continue
        base = os.path.dirname(p)
        for lineno, span in spans(md(p) if is_md else rs(p)):
            verdict = classify(span, base)
            counts[verdict] += 1
            if verdict == 'stale':
                hits.append('%s:%d: `%s`' % (p, lineno, normalize(span)))
print('%d %d %d %d %d %d' % (counts['ok'], counts['stale'], counts['feature'],
                             counts['shorthand'], counts['bare'], counts['superpowers']))
for h in hits:
    print(h)
PY
)
  summary=$(printf '%s\n' "$paths" | head -1)
  read -r p_ok p_stale p_feat p_short p_bare _ <<EOF
$summary
EOF
  if [ -z "$p_ok" ]; then
    printf '  skip  path-reference scan produced no result\n'
  else
    if [ "$p_stale" -gt 0 ]; then
      printf '%s\n' "$paths" | tail -n +2 | sed '/^$/d' | sed 's/^/    stale: /'
      printf '  FAIL  %s path reference(s) do not resolve from the referencing file\n' "$p_stale"
      fail=1
    else
      printf '  ok    %s repo path references resolve (file-relative, then repo root)\n' "$p_ok"
    fi
    printf '  info  skipped %s locator-less refs (no recoverable base) and %s `crate/feature` spans\n' \
      "$((p_short + p_bare))" "$p_feat"
    printf '        the locator-less refs are the false positives a naive sweep reports; see TODO.md\n'
  fi

  # (d) Report: the archive inventory size quoted in docs/README.md.
  # Hand-maintained counts go stale silently (it said 81 while the tree had a
  # different number), so measure it here and keep the doc's figure sourced.
  n_arch=$(find docs/archive -type f -name '*.md' ! -name 'README.md' | wc -l | tr -d ' ')
  sz_arch=$(du -sh docs/archive 2>/dev/null | cut -f1)
  printf '  info  archive inventory: %s dated documents (%s)\n' "$n_arch" "$sz_arch"
else
  printf '  skip  python3 not found — docs checks not evaluated\n'
fi

# ---------------------------------------------------------------- sizes
if [ "${1:-}" = "--sizes" ]; then
  hdr "Release binary sizes (slow — builds)"
  cargo build --release -p frps -p frpc >/dev/null 2>&1
  for b in frps frpc; do
    f="target/release/$b"
    [ -f "$f" ] && printf '  %-6s %s\n' "$b" "$(du -h "$f" | cut -f1)"
  done
else
  hdr "Release binary sizes"
  printf '  skipped (pass --sizes to build and measure)\n'
fi

hr
if [ "$fail" -eq 0 ]; then
  printf 'RESULT: invariants hold\n'
else
  printf 'RESULT: FAILURES above — fix before release\n'
fi
exit "$fail"
