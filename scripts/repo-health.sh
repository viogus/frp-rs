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
