#!/usr/bin/env bash
# todo-cite-guard-fixtures.sh — canary/fixture checks for
# `scripts/tests/todo-cite-guard.sh`.
#
# Why this exists: the cite gate's whole value is that it *reds*. A gate that
# silently stops scanning (a broken file list, an empty ledger, a regex that
# stops matching) prints `0 violation(s)` and exits 0, which looks exactly like
# a clean tree. Every scenario below therefore drives the gate against a
# synthetic tree and asserts both the exit code and the `file:line` it names.
#
# Scenarios
#   1  the gate is green when every live cite lands on a header;
#   2  a mid-item body cite reds and names the file and line (the common drift);
#   3  a cite past EOF reds;
#   4  a cite on a blank line reds;
#   5  an unparseable cite (a cite whose digits run into a letter) reds;
#   6  a point-in-time cite (TODO.md itself, docs/history, CHANGELOG.md,
#      docs/archive, docs/audit, performance-audit.md,
#      docs/refactor-large-modules.md) does NOT red, while a live cite beside it
#      still does — the classification is the gate's scope, so a scope that
#      drifts to "everything" would red the historical record and a scope that
#      drifts to "nothing" would pass scenario 2;
#   7  a `:NNNN` continuation after a full cite is checked (and reds);
#   8  a `:NNNN` that is not a continuation (a `file:line` in ordinary prose) is
#      not read as a ledger cite;
#   9  a blank line immediately after a full cite is not a continuation;
#   10 a `TODO.md` with no item headers is a hard failure, not "0 violations";
#   11 a missing ledger is a hard failure;
#   12 two cites on one line each name their own target;
#   13 a tree with no cites at all fails the floor rather than certifying
#      "nothing to check".
#
# Self-contained: no network, no compat run, no repo binaries. The synthetic
# trees live under `mktemp -d` and are removed on every exit path.
#
# Usage: bash scripts/tests/todo-cite-guard-fixtures.sh
set -uo pipefail

# Resolve this script through symlinks before deriving the repo root, the way
# the sibling suites do.
self=${BASH_SOURCE[0]:-$0}
case "$self" in
  */*) ;;
  *) if [ -e "$self" ]; then self=$PWD/$self; else self=$(command -v -- "$self") || {
       printf 'FAIL  cannot locate the harness: %s\n' "$0"; exit 1; }; fi ;;
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
SELF_REAL=$self
ROOT=$(cd -P -- "$(dirname -- "$self")/../.." && pwd)
GUARD="$ROOT/scripts/tests/todo-cite-guard.sh"

checks=0
fail=0
tmp=""
ok()  { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fail=1; printf '  FAIL  %s\n' "$1"; }
hdr() { printf '%s\n' "------------------------------------------------------------"; }

# The floor below is this suite's own self-defence (the same shape as the
# sibling suites): `exit "$fail"` alone is happy with no assertions at all.
MIN_CHECKS=40

cleanup_all() {
  local rc=$? min_raw
  [ -z "$tmp" ] || rm -rf "$tmp"
  if [ "$rc" -eq 0 ]; then
    case ${MIN_CHECKS:-} in
      ''|0)
        printf 'FAIL  the check floor is disabled (MIN_CHECKS=%s); the suite cannot vouch for itself\n' \
          "${MIN_CHECKS:-<unset>}" >&2
        rc=1 ;;
      *[!0-9]*)
        printf 'FAIL  the check floor is not a number (MIN_CHECKS=%s); the suite cannot vouch for itself\n' \
          "$MIN_CHECKS" >&2
        rc=1 ;;
      *)
        min_raw=$MIN_CHECKS
        while [ "${MIN_CHECKS#0}" != "$MIN_CHECKS" ]; do MIN_CHECKS=${MIN_CHECKS#0}; done
        if [ -z "$MIN_CHECKS" ]; then
          printf 'FAIL  the check floor is disabled (MIN_CHECKS=%s); the suite cannot vouch for itself\n' \
            "$min_raw" >&2
          rc=1
        else
          case $checks in
            ''|*[!0-9]*)
              printf 'FAIL  the check counter is not a number (%s); the suite cannot vouch for itself\n' \
                "$checks" >&2
              rc=1 ;;
            *)
              if [ "${#checks}" -lt "${#MIN_CHECKS}" ] ||
                { [ "${#checks}" -eq "${#MIN_CHECKS}" ] && [ "$checks" \< "$MIN_CHECKS" ]; }; then
                printf 'FAIL  suite exited 0 after only %s check(s); expected at least %s — scenarios did not run\n' \
                  "$checks" "$MIN_CHECKS" >&2
                rc=1
              fi ;;
          esac
        fi ;;
    esac
  fi
  exit "$rc"
}
trap cleanup_all EXIT

# Build a synthetic scan tree.
#   $1 = directory to build
#   $2 = the ledger's item-header text (a line written as `- [ ] **X**`)
#   $3 = bytes to append after that header (the ledger body)
# The scan tree is deliberately built WITHOUT `.git`, so the gate's
# filesystem-walk fallback is what finds the synthetic files — the suite must
# not depend on the real repo's index.
build_tree() {   # $1 = dir, $2 = header line, $3 = ledger body
  local d=$1 header=$2 body=$3
  rm -rf "$d"
  mkdir -p "$d/docs/history" "$d/docs/archive" "$d/docs/audit" "$d/src" "$d/scripts/tests"
  # A ledger with exactly three items: headers on lines 1, 5 and 9.
  {
    printf '%s\n' "$header"
    printf '  body line one\n'
    printf '  body line two\n'
    printf '\n'
    printf -- '- [x] **Second item.**\n'
    printf '  body\n'
    printf '  body\n'
    printf '\n'
    printf -- '- [ ] **Third item.**\n'
    printf '%s\n' "$body"
    printf '  body\n'
  } > "$d/TODO.md"
  printf '//! a live comment citing %s\n' "$(cite 1)" > "$d/src/live.rs"
}

# `cite()` below is the only place in this suite that builds a real ledger
# token. Keeping it in one function matters: this suite is itself scanned by
# the gate it drives, so a numbered token typed into these comments would be a
# real (and wrong) cite.
cite() { printf '%s:%s' 'TODO.md' "$1"; }
# The bare continuation token, built the same way.
bare() { printf ':%s' "$1"; }

run_gate() {   # $1 = tree, $2 = ledger path (default $1/TODO.md)
  # The floor is lowered to 1 (not 0) for the synthetic trees: they carry one
  # or two cites, far below the shipped floor of 20, and the gate rejects a
  # floor of 0 outright. Scenario 13 drives the shipped default and the
  # disabled-floor failure separately.
  local d=$1 led=${2:-$1/TODO.md} out rc
  out=$(TODO_CITE_MIN=1 bash "$GUARD" "$d" "$led" 2>&1)
  rc=$?
  LAST_OUT=$out
  LAST_RC=$rc
}

LAST_OUT=''
LAST_RC=''

hdr 'scenario 1 — clean synthetic tree is green'
tmp=$(mktemp -d) || { printf 'FAIL  mktemp failed\n' >&2; exit 1; }
build_tree "$tmp/t1" '- [ ] **First item.**' '  body'
run_gate "$tmp/t1"
if [ "$LAST_RC" -eq 0 ]; then
  ok 'clean tree: gate exited 0'
else
  bad "clean tree: gate exited $LAST_RC: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')"
fi
case $LAST_OUT in
  *'RESULT: 1 cite(s) checked, 0 violation(s)'*) ok 'clean tree: the gate reports 1 cite checked and 0 violations' ;;
  *) bad "clean tree: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 2 — a mid-item body cite reds (the common drift)'
build_tree "$tmp/t2" '- [ ] **First item.**' '  body'
printf '//! cites %s (mid-item body)\n' "$(cite 2)" > "$tmp/t2/src/drift.rs"
run_gate "$tmp/t2"
if [ "$LAST_RC" -ne 0 ]; then
  ok "mid-item cite: gate exited $LAST_RC"
else
  bad 'mid-item cite: gate exited 0 — a body-line cite was certified'
fi
case $LAST_OUT in
  *'src/drift.rs:1'*) ok 'mid-item cite: the gate names the offending file:line' ;;
  *) bad "mid-item cite: the failure does not name src/drift.rs:1: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
case $LAST_OUT in
  *'RESULT: 2 cite(s) checked, 1 violation(s)'*) ok 'mid-item cite: the summary counts the cite and the violation' ;;
  *) bad "mid-item cite: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 3 — a cite past EOF reds'
build_tree "$tmp/t3" '- [ ] **First item.**' '  body'
printf '//! cites %s (past EOF)\n' "$(cite 999999)" > "$tmp/t3/src/eof.rs"
run_gate "$tmp/t3"
if [ "$LAST_RC" -ne 0 ]; then ok "past-EOF cite: gate exited $LAST_RC"; else bad 'past-EOF cite: gate exited 0'; fi
case $LAST_OUT in
  *'src/eof.rs:1'*'past EOF'*) ok 'past-EOF cite: named with the past-EOF reason' ;;
  *) bad "past-EOF cite: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 4 — a cite on a blank ledger line reds'
# Ledger line 4 is the blank separator; cite it.
build_tree "$tmp/t4" '- [ ] **First item.**' '  body'
printf '//! cites %s (blank line)\n' "$(cite 4)" > "$tmp/t4/src/blank.rs"
run_gate "$tmp/t4"
if [ "$LAST_RC" -ne 0 ]; then ok "blank-line cite: gate exited $LAST_RC"; else bad 'blank-line cite: gate exited 0'; fi
case $LAST_OUT in
  *'src/blank.rs:1'*'blank line'*) ok 'blank-line cite: named with the blank-line reason' ;;
  *) bad "blank-line cite: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 5 — an unparseable cite reds'
build_tree "$tmp/t5" '- [ ] **First item.**' '  body'
printf '//! cites %s:%s here\n' 'TODO.md' '12x' > "$tmp/t5/src/bad.rs"
run_gate "$tmp/t5"
if [ "$LAST_RC" -ne 0 ]; then ok "unparseable cite: gate exited $LAST_RC"; else bad 'unparseable cite: gate exited 0'; fi
case $LAST_OUT in
  *'src/bad.rs:1'*'unparseable'*) ok 'unparseable cite: named with the unparseable reason' ;;
  *) bad "unparseable cite: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 6 — point-in-time documents are out of scope'
build_tree "$tmp/t6" '- [ ] **First item.**' '  body'
# Every point-in-time file gets a cite to a mid-item body line: if the scope
# widens to "everything", the gate reds on these.
printf 'body cites %s\n' "$(cite 2)" >> "$tmp/t6/TODO.md"
printf 'changelog cites %s\n' "$(cite 2)" > "$tmp/t6/CHANGELOG.md"
printf 'audit cites %s\n' "$(cite 2)" > "$tmp/t6/performance-audit.md"
printf 'plan cites %s\n' "$(cite 2)" > "$tmp/t6/docs/refactor-large-modules.md"
printf 'history cites %s\n' "$(cite 2)" > "$tmp/t6/docs/history/development-log.md"
printf 'archive cites %s\n' "$(cite 2)" > "$tmp/t6/docs/archive/old.md"
printf 'auditdir cites %s\n' "$(cite 2)" > "$tmp/t6/docs/audit/finding.md"
# Add a live cite too, so the run still has something to check.
printf '//! live cites %s\n' "$(cite 1)" > "$tmp/t6/src/live2.rs"
run_gate "$tmp/t6"
if [ "$LAST_RC" -eq 0 ]; then
  ok 'point-in-time scope: the six historical files do not red the gate'
else
  bad "point-in-time scope: gate exited $LAST_RC: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')"
fi
case $LAST_OUT in
  *'RESULT: 2 cite(s) checked, 0 violation(s)'*) ok 'point-in-time scope: only the two live cites were checked' ;;
  *) bad "point-in-time scope: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
# ... and a live file beside them still reds, so the scope is not "nothing".
printf '//! live drift cites %s\n' "$(cite 3)" > "$tmp/t6/src/drift2.rs"
run_gate "$tmp/t6"
if [ "$LAST_RC" -ne 0 ]; then
  ok 'point-in-time scope: a live drift cite beside the historical files still reds'
else
  bad 'point-in-time scope: widening the scope to point-in-time hid a live violation'
fi
case $LAST_OUT in
  *'src/drift2.rs:1'*) ok 'point-in-time scope: the live violation names src/drift2.rs:1' ;;
  *) bad "point-in-time scope: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 7 — the `:NNNN` continuation form is checked'
build_tree "$tmp/t7" '- [ ] **First item.**' '  body'
printf '//! cites %s, %s (continuation)\n' "$(cite 1)" "$(bare 6)" > "$tmp/t7/src/cont.rs"
run_gate "$tmp/t7"
if [ "$LAST_RC" -ne 0 ]; then
  ok "continuation cite: gate exited $LAST_RC on a bad continuation"
else
  bad 'continuation cite: a mid-item continuation was not checked'
fi
case $LAST_OUT in
  *'src/cont.rs:1'*) ok 'continuation cite: the gate names the line carrying it' ;;
  *) bad "continuation cite: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
case $LAST_OUT in
  *'RESULT: 3 cite(s) checked, 1 violation(s)'*) ok 'continuation cite: both cites were counted' ;;
  *) bad "continuation cite: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
# The good half: a continuation that lands on a header stays green.
printf '//! cites %s, %s (continuation)\n' "$(cite 1)" "$(bare 9)" > "$tmp/t7/src/cont.rs"
run_gate "$tmp/t7"
if [ "$LAST_RC" -eq 0 ]; then
  ok 'continuation cite: a header-landing continuation stays green'
else
  bad "continuation cite: a header-landing continuation red: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')"
fi

hdr 'scenario 8 — a `file:line` that is not a continuation is not a ledger cite'
build_tree "$tmp/t8" '- [ ] **First item.**' '  body'
printf '//! see `src/live.rs:7` and `frp-core/src/cli.rs:590` for the anchor\n' > "$tmp/t8/src/other.rs"
run_gate "$tmp/t8"
if [ "$LAST_RC" -eq 0 ]; then
  ok 'non-continuation `file:line`: not read as a ledger cite'
else
  bad "non-continuation `file:line`: gate exited $LAST_RC: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')"
fi
case $LAST_OUT in
  *'RESULT: 1 cite(s) checked, 0 violation(s)'*) ok 'non-continuation `file:line`: only the real cite was counted' ;;
  *) bad "non-continuation `file:line`: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 9 — a blank line after a cite is not a continuation'
build_tree "$tmp/t9" '- [ ] **First item.**' '  body'
{
  printf '//! cites %s\n' "$(cite 1)"
  printf '\n'
  printf '//! ordinary prose, then a bare number in a list:\n'
  printf '//!   %s\n' "$(bare 6)"
} > "$tmp/t9/src/wrap.rs"
run_gate "$tmp/t9"
if [ "$LAST_RC" -eq 0 ]; then
  ok 'wrapped-cite guard: a bare `:NNNN` not attached to a cite stays out of scope'
else
  bad "wrapped-cite guard: gate exited $LAST_RC: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')"
fi
case $LAST_OUT in
  *'RESULT: 2 cite(s) checked, 0 violation(s)'*) ok 'wrapped-cite guard: only the two real cites were counted' ;;
  *) bad "wrapped-cite guard: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 10 — a ledger with no item headers is a hard failure'
build_tree "$tmp/t10" '- [ ] **First item.**' '  body'
printf 'no headers here\njust prose\n' > "$tmp/t10/TODO.md"
run_gate "$tmp/t10"
if [ "$LAST_RC" -ne 0 ]; then
  ok "header floor: a headerless ledger exits $LAST_RC"
else
  bad 'header floor: a headerless ledger exited 0 — every cite would have "resolved" vacuously'
fi
case $LAST_OUT in
  *'carries no item headers'*) ok 'header floor: the failure names the missing headers' ;;
  *) bad "header floor: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 11 — a missing ledger is a hard failure'
build_tree "$tmp/t11" '- [ ] **First item.**' '  body'
run_gate "$tmp/t11" "$tmp/t11/NO-SUCH-TODO.md"
if [ "$LAST_RC" -ne 0 ]; then
  ok "missing ledger: exits $LAST_RC"
else
  bad 'missing ledger: exited 0'
fi
case $LAST_OUT in
  *'no ledger to check cites against'*) ok 'missing ledger: the failure names the missing ledger' ;;
  *) bad "missing ledger: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 12 — two cites on one line each name their own target'
build_tree "$tmp/t12" '- [ ] **First item.**' '  body'
printf '//! %s and %s\n' "$(cite 1)" "$(cite 6)" > "$tmp/t12/src/two.rs"
run_gate "$tmp/t12"
if [ "$LAST_RC" -ne 0 ]; then
  ok "two-on-a-line: the bad half reds (exit $LAST_RC)"
else
  bad 'two-on-a-line: the bad half was not checked'
fi
case $LAST_OUT in
  *'src/two.rs:1'*'not an item header'*) ok 'two-on-a-line: the failure names the line and the reason' ;;
  *) bad "two-on-a-line: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
case $LAST_OUT in
  *'RESULT: 3 cite(s) checked, 1 violation(s)'*) ok 'two-on-a-line: both cites counted, one violation' ;;
  *) bad "two-on-a-line: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 12b — a nested `file:line: "text"` reference is not a citation'
build_tree "$tmp/t12b" '- [ ] **First item.**' '  body'
printf '//! see `src/live.rs:7: "the anchor"` in the prose above\n' > "$tmp/t12b/src/nested.rs"
run_gate "$tmp/t12b"
if [ "$LAST_RC" -eq 0 ]; then
  ok 'nested `file:line: "text"`: not read as a ledger cite'
else
  bad "nested `file:line: \"text\"`: gate exited $LAST_RC: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')"
fi
case $LAST_OUT in
  *'RESULT: 1 cite(s) checked, 0 violation(s)'*) ok 'nested `file:line: "text"`: only the real cite was counted' ;;
  *) bad "nested `file:line: \"text\"`: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 13 — a tree with no cites fails the floor'
build_tree "$tmp/t13" '- [ ] **First item.**' '  body'
rm -f "$tmp/t13/src/live.rs"
run_gate "$tmp/t13"
if [ "$LAST_RC" -ne 0 ]; then
  ok "empty scan: exits $LAST_RC"
else
  bad 'empty scan: exited 0 — a broken scan was certified as clean'
fi
# The fixture suite turns the floor off for the other scenarios, so this one
# runs the gate with the real floor and a synthetic tree too small for it.
# `TODO_CITE_MIN` is deliberately unset here (only `run_gate` sets it).
out=$(bash "$GUARD" "$tmp/t13" "$tmp/t13/TODO.md" 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then
  ok "empty scan: the shipped floor refuses the cite-less tree (exit $rc)"
else
  bad 'empty scan: the shipped floor certified a cite-less tree'
fi
case $out in
  *'the scan is broken, not the tree clean'*) ok 'empty scan: the failure explains the broken scan' ;;
  *) bad "empty scan: unexpected failure text: $(printf '%s' "$out" | tr '\n' ' ')" ;;
esac
# A floor of 0 is rejected by the gate itself, so the seam cannot be turned
# into "check nothing" by a caller.
out=$(TODO_CITE_MIN=0 bash "$GUARD" "$tmp/t13" "$tmp/t13/TODO.md" 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then
  ok 'zero floor: the gate refuses TODO_CITE_MIN=0'
else
  bad 'zero floor: the gate accepted TODO_CITE_MIN=0'
fi
case $out in
  *'the cite floor is disabled'*) ok 'zero floor: the failure names the disabled floor' ;;
  *) bad "zero floor: unexpected failure text: $(printf '%s' "$out" | tr '\n' ' ')" ;;
esac

hdr 'scenario 14 — the gate is self-contained and read-only'
if [ -f "$GUARD" ]; then
  ok 'the gate script exists at scripts/tests/todo-cite-guard.sh'
else
  bad "the gate script is missing: $GUARD"
fi
if grep -q 'TODO_CITE_MIN' "$GUARD"; then
  ok 'the gate exposes the TODO_CITE_MIN floor the fixtures drive'
else
  bad 'the gate does not expose the TODO_CITE_MIN seam'
fi
# The gate must not write into the tree it scans.
before=$(cd -P -- "$tmp/t1" && find . | sort)
run_gate "$tmp/t1"
after=$(cd -P -- "$tmp/t1" && find . | sort)
if [ "$before" = "$after" ]; then
  ok 'the gate leaves the scanned tree untouched'
else
  bad 'the gate modified the tree it scanned'
fi

hdr 'summary'
if [ "$fail" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
else
  printf 'RESULT: %d fixture check(s), %d failure(s) above\n' "$checks" "$fail"
fi
exit "$fail"
