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
# corresponding FAIL row carries the gate's own `(exit 3)` annotation. A
# throwaway tree is enough because repo-health.sh runs its sections top to
# bottom and never exits early on a *failed* gate — it reaches the gate under
# test regardless of the unrelated FAILs a bare tree produces.
#
# Self-contained: no network, no dependence on this repo's contents (the tree is
# built from scratch and only the script under test is copied in), and the
# temporary tree is removed on exit.
#
# Usage: bash scripts/tests/repo-health-fixtures.sh
set -uo pipefail

self=${BASH_SOURCE[0]:-$0}
case "$self" in
  */*) ;;
  *) self=$PWD/$self ;;
esac
cd -P -- "$(dirname -- "$self")/../.." || exit 1
RH=$PWD/scripts/repo-health.sh
if [ ! -f "$RH" ]; then
  printf 'FAIL  cannot find the script under test: %s\n' "$RH"
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

# run_gate <tree> — run the copied script from inside the tree; sets rc and out.
run_gate() {
  out=$(cd "$1" && bash scripts/repo-health.sh 2>&1)
  rc=$?
}

# assert_exit_mapping <label> — the process rc is 1 (never 3), and at least one
# FAIL row names the gate's own exit code as `(exit 3)`.
assert_exit_mapping() {
  if [ "$rc" -eq 1 ]; then
    ok "$1: process rc is 1"
  else
    bad "$1: process rc is $rc (expected 1 — a bare exit 3/fail=3 regression?)"
  fi
  if printf '%s\n' "$out" | grep -q '^  FAIL  .*(exit 3)'; then
    ok "$1: a FAIL row carries the gate's (exit 3) annotation"
  else
    bad "$1: no FAIL row annotated (exit 3) — the mapping drifted"
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
assert_exit_mapping 'exit-3 gate'
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

# ---------------------------------------------------------------- summary
hdr
if [ "$fail" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
else
  printf 'RESULT: %d fixture check(s), failures above\n' "$checks"
fi
exit "$fail"
