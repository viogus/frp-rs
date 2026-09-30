#!/usr/bin/env bash
# repo-health-fixtures.sh — fixture-based checks for scripts/repo-health.sh.
#
# Why this exists: repo-health.sh runs its gates as python programs and maps a
# gate's *own* exit code onto the wrapper's exit code. That mapping is not
# visible from the printed report alone, and two drifts are possible while every
# other check stays green:
#   * a bare `exit 3` (or `fail=3`) at the top level would make the *process*
#     exit 3, which the documented contract (0, or 1 on any failure) forbids;
#   * a claim that "the gate exits 3" about the *process* rather than about the
#     gate would stop matching the wrapper.
#
# This harness builds throwaway trees under `mktemp -d`, runs the script under
# test inside them, and pins both halves: the process rc is 1 (never 3), and the
# gate's *own* row is printed (naming `(exit 3)`). The row must be the specific
# one — "some row carries `(exit 3)`" is vacuous, because a bare tree already
# prints two unrelated `(exit 3)` rows. A throwaway tree is enough because
# repo-health.sh runs its sections top to bottom and never exits early on a
# *failed* gate — it reaches the gate under test regardless of the unrelated
# FAILs a bare tree produces.
#
# Later scenarios go past the exit-code mapping, because a positive check alone
# cannot show that the fixture drives the code it claims to: scenario 4 builds
# the stub inputs that let all four `.rs` walks run and then reverts each walk's
# fall-through in the tree's own copy of the script, one at a time, so the checks
# are shown to red on the right edit; scenario 5 is the clean-tree negative
# control for scenario 1's row; scenario 6 asserts the integration-test-dir
# metric, whose `scripts/tests/` blind spot is why it exists.
#
# Self-contained: no network, no dependence on this repo's contents (the tree is
# built from scratch and only the script under test is copied in), and the
# temporary tree is removed on exit.
#
# Usage: bash scripts/tests/repo-health-fixtures.sh
#        (also correct when the harness itself is invoked through a symlink)
set -uo pipefail

self=${BASH_SOURCE[0]:-$0}
case "$self" in
  */*) ;;
  *) if [ -e "$self" ]; then
       self=$PWD/$self
     else
       self=$(command -v -- "$self") || {
         printf 'FAIL  cannot locate the harness: %s\n' "$0"; exit 1; }
     fi ;;
esac
# Follow symlinks to the real file before deriving the repo root. Without this,
# invoking the harness through a symlink (a `ln -s … /tmp/rhfx.sh`, or a wrapper
# in another directory) resolved `../..` against the *link's* directory and looked
# for `//scripts/repo-health.sh`. `readlink -f` is not POSIX and older macOS/BSD
# releases lack it, so loop on plain `readlink`, resolving each target against the
# link's own directory. Bounded so a symlink cycle cannot hang the run.
n=0
while [ -L "$self" ]; do
  dir=$(cd -P -- "$(dirname -- "$self")" && pwd) || exit 1
  link=$(readlink -- "$self") || exit 1
  case "$link" in
    /*) self=$link ;;
    *)  self=$dir/$link ;;
  esac
  n=$((n + 1))
  if [ "$n" -gt 40 ]; then
    printf 'FAIL  cannot resolve the harness path (symlink cycle?): %s\n' "$0"
    exit 1
  fi
done
cd -P -- "$(dirname -- "$self")/../.." || exit 1
RH=$PWD/scripts/repo-health.sh
if [ ! -f "$RH" ]; then
  printf 'FAIL  cannot find the script under test: %s\n' "$RH"
  exit 1
fi
RC_PY=$PWD/scripts/rust_comments.py
if [ ! -f "$RC_PY" ]; then
  printf 'FAIL  cannot find the module the script under test imports: %s\n' "$RC_PY"
  exit 1
fi

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

checks=0
fail=0
ok()  { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fail=1; printf '  FAIL  %s\n' "$1"; }
hdr() { printf '%s\n' "------------------------------------------------------------"; }

printf '%s\n' 'repo-health.sh fixture checks'

# new_tree <name> — print the path of a throwaway root carrying the script under
# test at scripts/repo-health.sh and an empty docs/archive/.
new_tree() {
  d=$tmp/$1
  mkdir -p "$d/scripts" "$d/docs/archive" "$d/.github/workflows"
  cp "$RH" "$d/scripts/repo-health.sh"
  printf '%s\n' "$d"
}

# new_full_tree <name> — new_tree plus the stub measurement inputs that let every
# `.rs` walk actually run. A bare tree cannot show that: the Unsafe usage table
# and the SAFETY scan die on `import rust_comments` (no scripts/ module), and the
# fourth walk (`unsafe_counts` in the doc-figures block) is never reached because
# the preflight reports the missing measurement inputs first and exits. The stubs
# are deliberately minimal — the doc-figure claims below them will not match, so
# the tree is red anyway; that is fine, the checks read per-walk rows.
new_full_tree() {
  d=$(new_tree "$1")
  mkdir -p "$d/frp-core/src" "$d/frp-vnet/src" "$d/frp-core/benches" \
           "$d/frp-server/benches" "$d/vendor/rustls" "$d/vendor/yamux" \
           "$d/vendor/russh"
  cp "$RC_PY" "$d/scripts/rust_comments.py"
  # `--list` must yield a non-empty token list or count_compat() reports a
  # partial tree and exits before unsafe_counts (site 4) runs.
  cat > "$d/scripts/compat-test.sh" <<'STUB'
#!/usr/bin/env bash
if [ "${1:-}" = "--list" ]; then printf 'test_alpha\ntest_beta\n'; fi
exit 0
STUB
  printf '#!/usr/bin/env bash\nexit 0\n' > "$d/scripts/protocol-matrix.sh"
  printf '[package]\nname = "frp-core"\nversion = "0.71.0"\n' > "$d/frp-core/Cargo.toml"
  for v in rustls yamux russh; do
    printf '[package]\nname = "%s"\nversion = "1.2.3"\n' "$v" > "$d/vendor/$v/Cargo.toml"
  done
  printf 'pub fn placeholder() {}\n' > "$d/frp-core/src/lib.rs"
  printf 'pub fn placeholder() {}\n' > "$d/frp-vnet/src/lib.rs"
  printf 'pub fn placeholder() {}\n' > "$d/frp-core/benches/crypto_bridge.rs"
  printf 'pub fn placeholder() {}\n' > "$d/frp-server/benches/nathole.rs"
  printf '%s\n' "$d"
}

# mut_rwalk <tree> <site> — revert, in the tree's copy of the script, the "a file
# that cannot be stat-ed is still read, so its error is reported" fall-through at
# one of the four `.rs` walk sites. Site 1 is `rs_texts`' `fresh()`; sites 2-4 are
# the three inline walks in file order (Unsafe usage table, SAFETY scan,
# unsafe_counts). The anchor count is asserted, so a refactor that moves the code
# fails the mutation loudly instead of mutating nothing — which would leave the
# teeth-checks vacuously green.
mut_rwalk() {
  python3 - "$1" "$2" <<'PY'
import sys
tree, site = sys.argv[1], int(sys.argv[2])
p = tree + '/scripts/repo-health.sh'
s = open(p).read()
if site == 1:
    old = '        except OSError:\n            return os.path.realpath(path)'
    assert s.count(old) == 1, 'site 1 anchor found %d times' % s.count(old)
    s = s.replace(old, '        except OSError:\n            return None', 1)
else:
    old = 'key = real'
    assert s.count(old) == 3, 'site 2-4 anchor found %d times' % s.count(old)
    i = -1
    for _ in range(site - 1):
        i = s.find(old, i + 1)
    s = s[:i] + 'continue' + s[i + len(old):]
open(p, 'w').write(s)
PY
}

# out_count <needle> — how many lines of the last run_gate output contain it.
out_count() { printf '%s\n' "$out" | grep -cF -- "$1"; }

# run_gate <tree> — run the copied script from inside the tree; sets rc and out.
run_gate() {
  out=$(cd "$1" && bash scripts/repo-health.sh 2>&1)
  rc=$?
}

# assert_exit_mapping <label> <exact FAIL row> — the process rc is 1 (never 3),
# and that specific row is printed. Measured vacuity of the looser check: a bare
# tree already prints `path-reference scan produced no result (exit 3)` and
# `doc figures not evaluated — the tree is partial (exit 3)`, so `rc=1` plus
# "some `(exit 3)` row" held with the archive gate's own `sys.exit(3)` changed
# to `sys.exit(0)` *and* with that row's annotation reworded.
assert_exit_mapping() {
  if [ "$rc" -eq 1 ]; then
    ok "$1: process rc is 1"
  else
    bad "$1: process rc is $rc (expected 1 — a bare exit 3/fail=3 regression?)"
  fi
  if printf '%s\n' "$out" | grep -qF -- "$2"; then
    ok "$1: the expected FAIL row is printed"
  else
    bad "$1: expected FAIL row missing: $2"
  fi
}

# --- scenario 1: a gate exits 3 ---------------------------------------------
# A dangling symlink under docs/archive/ makes the archive-path scan record a
# read error and exit 3; the wrapper must still return 1 and say `(exit 3)`.
hdr
printf '%s\n' 'scenario 1: a gate exits 3 (dangling docs/archive symlink)'
t=$(new_tree exit3)
ln -s nowhere.md "$t/docs/archive/bad.md"
run_gate "$t"
assert_exit_mapping 'exit-3 gate' '  FAIL  archive path scan failed (exit 3)'
if [ "$rc" -eq 3 ]; then
  bad 'the process itself exited 3 (a bare exit 3/fail=3 at top level)'
fi

# --- scenario 2: a newline in a workflow filename ---------------------------
# The scan hands hits to bash as `C <path>:<line>:<text>` lines, so a workflow
# whose own name contains a newline split a hit and had the fragment re-parsed
# as a hit of its own (a fabricated `toolchain:` violation). The path must be
# refused fail-closed: the refusal names it (sanitized), nothing in it is
# scanned, and no forged hit is printed.
hdr
printf '%s\n' 'scenario 2: a workflow filename containing a newline'
t=$(new_tree newline)
wf="$t/.github/workflows/"$'a\nC forged.yml'
printf 'name: probe\non: push\njobs:\n  a:\n    steps:\n      - uses: actions-rust-lang/setup-rust-toolchain@v1\n        with:\n          toolchain: 1.98.0\n' > "$wf"
run_gate "$t"
if printf '%s\n' "$out" | grep -q 'workflow path with a newline in its name was not scanned'; then
  ok 'newline path: the workflow is refused by name'
else
  bad 'newline path: no refusal naming the workflow'
fi
if printf '%s\n' "$out" | grep -q 'toolchain:.*input(s)'; then
  bad 'newline path: a forged toolchain: hit was parsed from the split line'
else
  ok 'newline path: no forged hit from the split path'
fi
if printf '%s\n' "$out" | grep -q 'toolchain input scan not evaluated'; then
  ok 'newline path: the scan reports itself not evaluated (fail-closed)'
else
  bad 'newline path: the scan did not report itself not evaluated'
fi
if [ "$rc" -eq 1 ]; then
  ok 'newline path: process rc is 1'
else
  bad "newline path: process rc is $rc (expected 1)"
fi

# --- scenario 3: a newline in a workflow *directory* ------------------------
# The guard must test the whole path, not the basename: a directory named
# `sub<LF>C forged.yml` around a `probe.yml` carrying a floating-toolchain line
# makes the scan print a `D <path>:<line>:<text>` hit whose first line is the
# directory fragment; the `C ` rest is then re-parsed as a fabricated
# `toolchain:` input (measured: `FAIL 1 toolchain: input(s)`).
hdr
printf '%s\n' 'scenario 3: a workflow directory containing a newline'
t=$(new_tree newline-dir)
dir="$t/.github/workflows/"$'sub\nC forged.yml'
mkdir -p "$dir"
printf 'name: probe\non: push\njobs:\n  a:\n    steps:\n      - run: rustup default stable\n' > "$dir/probe.yml"
run_gate "$t"
if printf '%s\n' "$out" | grep -q 'workflow path with a newline in its name was not scanned'; then
  ok 'newline dir: the workflow is refused by name'
else
  bad 'newline dir: no refusal naming the workflow'
fi
if printf '%s\n' "$out" | grep -q 'toolchain:.*input(s)'; then
  bad 'newline dir: a forged toolchain: hit was parsed from the split line'
else
  ok 'newline dir: no forged hit from the split path'
fi
if printf '%s\n' "$out" | grep -q 'toolchain input scan not evaluated'; then
  ok 'newline dir: the scan reports itself not evaluated (fail-closed)'
else
  bad 'newline dir: the scan did not report itself not evaluated'
fi
if [ "$rc" -eq 1 ]; then
  ok 'newline dir: process rc is 1'
else
  bad "newline dir: process rc is $rc (expected 1)"
fi

# --- scenario 4: an unreadable .rs reaches every walk site ------------------
# Containment must not be checked before readability: a dangling symlink in
# `frp-core/src/` resolves *outside* the crate, and skipping it there hides the
# read error, so a source-count gate would print `ok` over an unreadable input.
# Four separate `.rs` walks exist, and a bare tree pins only the first, so the
# fixture supplies the stub inputs that let all four run and pins each site's own
# evidence: the path is reported by the three read-scope walks (site 1 walks two
# scopes, hence 4 lines) and named by the doc-figures block as a partial tree.
# The four mutants below are what give those two checks teeth — reverting the
# fall-through at any one site drops its line(s), or the partial-tree row.
hdr
printf '%s\n' "scenario 4: an unreadable .rs reaches every walk site"
t=$(new_full_tree unreadable)
ln -s nowhere "$t/frp-core/src/zz_broken.rs"
run_gate "$t"
n=$(out_count 'scan error: frp-core/src/zz_broken.rs')
if [ "$n" -eq 4 ]; then
  ok 'unreadable src: reported by all three read-scope walks (4 = src + crate scope)'
else
  bad "unreadable src: expected 4 scan-error lines, got $n"
fi
if printf '%s\n' "$out" | grep -qF 'partial tree: frp-core/src/zz_broken.rs is missing'; then
  ok 'unreadable src: the doc-figures block reports it as a partial tree (site 4)'
else
  bad 'unreadable src: unsafe_counts dropped the broken path (site 4)'
fi
if [ "$rc" -eq 1 ]; then
  ok 'unreadable src: process rc is 1'
else
  bad "unreadable src: process rc is $rc (expected 1)"
fi
for site in 1 2 3 4; do
  t=$(new_full_tree "unreadable-mut$site")
  ln -s nowhere "$t/frp-core/src/zz_broken.rs"
  mut_rwalk "$t" "$site"
  run_gate "$t"
  if [ "$site" -eq 4 ]; then
    # Site 4 emits no `scan error:` line (it raises out of the whole block), so
    # its revert is pinned by the partial-tree row instead of the count.
    if printf '%s\n' "$out" | grep -qF 'partial tree: frp-core/src/zz_broken.rs is missing'; then
      bad "unreadable src: site $site reverted but the partial-tree row survived"
    else
      ok "unreadable src: site $site revert drops the partial-tree row (check has teeth)"
    fi
  else
    n=$(out_count 'scan error: frp-core/src/zz_broken.rs')
    if [ "$n" -eq 4 ]; then
      bad "unreadable src: site $site reverted but all 4 scan-error lines survived"
    else
      ok "unreadable src: site $site revert drops its line(s) ($n left — check has teeth)"
    fi
  fi
done

# --- scenario 5: the archive (exit 3) row is not printed unconditionally ----
# Negative control for scenario 1: a wrapper that printed the `(exit 3)` row
# without the gate having exited 3 would satisfy scenario 1 while the report no
# longer reflects the gate at all.
hdr
printf '%s\n' 'scenario 5: the archive exit-3 row is absent when the scan succeeds'
t=$(new_tree clean-archive)
run_gate "$t"
if printf '%s\n' "$out" | grep -qF '  FAIL  archive path scan failed'; then
  bad 'clean archive scan: the archive exit-3 row was printed anyway'
else
  ok 'clean archive scan: no archive exit-3 row'
fi

# --- scenario 6: the integration-test-dir metric, with its heuristic ---------
# The metric counts `tests/` directories that carry at least one `.rs` file
# beneath them (a `.rs` anywhere below counts, however deep; a `tests/` dir with
# no `.rs` is dropped). Asserted, not described: a `scripts/tests/` holding a
# non-Rust file must not count, so this pins the F4 fix that stopped the harness'
# own script directory from inflating the number, and both the nested-file rule
# and the "has a .rs" rule at once.
hdr
printf '%s\n' 'scenario 6: the integration-test-dir metric counts only .rs-bearing tests/'
t=$(new_tree testdirs)
mkdir -p "$t/scripts/tests" "$t/frp-core/tests" "$t/frp-vnet/tests/deep"
printf '#!/bin/sh\n:\n' > "$t/scripts/tests/not-rust.sh"
printf 'fn t() {}\n' > "$t/frp-core/tests/it.rs"
printf 'fn u() {}\n' > "$t/frp-vnet/tests/deep/nested.rs"
run_gate "$t"
if printf '%s\n' "$out" | grep -qF 'integration test dirs: 2'; then
  ok 'integration test dirs: 2 (scripts/tests dropped; nested .rs counted)'
else
  bad "integration test dirs: expected 2, got $(printf '%s\n' "$out" | grep -F 'integration test dirs' || echo none)"
fi

# ---------------------------------------------------------------- summary
hdr
if [ "$fail" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
else
  printf 'RESULT: %d fixture check(s), failures above\n' "$checks"
fi
exit "$fail"
