#!/usr/bin/env bash
# pathline-cite-fixtures.sh — canary/fixture checks for
# `scripts/tests/pathline-cite-guard.sh`.
#
# Why this exists: the gate's whole value is that it *reds*. A gate whose scan
# stops finding cites, whose fingerprint comparison is neutered, or whose data
# file is silently absent prints `0 violation(s)` and exits 0, which is exactly
# what a clean tree prints. Every scenario below therefore drives the real guard
# against a synthetic tree and asserts both the exit code and the `file:line`
# the guard names.
#
# Scenarios
#   1  a clean synthetic tree is green and reports its checked count;
#   2  a one-line insert above a cited line reds, naming the citing file:line
#      and the target (the falsification the item asks for);
#   3  a deleted cite reds ("the expectation table records this cite but the
#      tree does not carry it");
#   4  a renumbered cite reds ("no expectation for this cite");
#   5  an absent expectation table is a hard failure, never a green run;
#   6  an empty expectation table is a hard failure;
#   7  a malformed record is a hard failure;
#   8  a cite past EOF reds;
#   9  a cite to a blank line reds (a blank line carries no text to pin);
#   10 the point-in-time set is excluded as a *target* (reported, not red) and as
#      a citing file (never scanned);
#   11 a `:NNN` shorthand is checked, and the shorthand and its anchor move
#      independently — a moved anchor reds the anchor only, a moved shorthand
#      target reds the shorthand only;
#   12 an unanchored bare `:NNN` is prose, not a cite;
#   13 a token naming a file this tree does not contain is out of tree, not a
#      cite (and is reported as such);
#   14 a `, N` continuation of a citation list is checked, and its own target
#      moving reds it;
#   15 an ambiguous path (a basename matching two tracked files) is reported as
#      unvalidatable and pinned: a second one reds the pin;
#   16 a weakly anchored cite (the cited line's text repeats in its file) is
#      reported and pinned: a second one reds the pin;
#   17 the cite floor: too few cites reds, and a disabled/zero-padded floor reds;
#   18 the expectation table is never scanned as a citing file, even when it
#      lives inside the tree;
#   19 `--write` is idempotent and reports the added/removed delta;
#   20 a failing `git ls-files` is a hard failure, not a partial tree.
#
# Self-contained: no network, no cargo, no compat run. Synthetic trees live
# under `mktemp -d` and are removed on every exit path.
#
# Usage: bash scripts/tests/pathline-cite-fixtures.sh
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
ROOT=$(cd -P -- "$(dirname -- "$self")/../.." && pwd)
GUARD="$ROOT/scripts/tests/pathline-cite-guard.sh"

checks=0
fails=0
tmp=""
LAST_OUT=''
LAST_RC=0
FLOOR_EXEMPT=""

# The floor below is this suite's own self-defence (the same shape as the
# sibling suites): `exit "$fails"` alone is happy with no assertions at all.
MIN_CHECKS=55

# shellcheck disable=SC2329  # invoked by the EXIT trap below, not directly
cleanup_all() {
  local rc=$? min_raw
  [ -z "$tmp" ] || rm -rf "$tmp"
  if [ "$rc" -eq 0 ] && [ -z "$FLOOR_EXEMPT" ]; then
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
        elif [ "$checks" -lt "$MIN_CHECKS" ]; then
          printf 'FAIL  suite exited 0 after only %s check(s); expected at least %s — scenarios did not run\n' \
            "$checks" "$MIN_CHECKS" >&2
          rc=1
        fi ;;
    esac
  fi
  exit "$rc"
}
trap cleanup_all EXIT

ok()  { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf '  FAIL  %s\n' "$1"; }
hdr() { printf '%s\n' "------------------------------------------------------------"; }

if [ ! -f "$GUARD" ]; then
  printf 'FAIL  cannot locate scripts/tests/pathline-cite-guard.sh from %s\n' "$ROOT" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  printf 'SKIP  python3 not found — the cite gate cannot be evaluated\n'
  FLOOR_EXEMPT=1
  exit 0
fi

# Build a synthetic scan tree. Every path here is deliberately absent from the
# real repository (`fx/...`, `notes.md`, `dup.rs`), so the literals this file
# carries are out-of-tree tokens for the real gate rather than cites of it.
build_tree() {   # $1 = directory
  local d=$1
  rm -rf "$d"
  mkdir -p "$d/fx/two_a" "$d/fx/two_b" "$d/docs/history" "$d/docs/archive" \
           "$d/docs/audit" "$d/scripts/tests"
  printf 'one\ntwo\nthree\nfour\nfive\n' > "$d/fx/anchor.rs"
  printf 'other one\nother two\n' > "$d/fx/other.rs"
  printf 'dup one\n' > "$d/fx/two_a/dup.rs"
  printf 'dup two\n' > "$d/fx/two_b/dup.rs"
  printf 'repeat A\nrepeat A\n' > "$d/fx/repeat.rs"
  printf 'TODO item one\nTODO item two\n' > "$d/TODO.md"
  printf 'changelog line\n' > "$d/CHANGELOG.md"
  printf 'history line\n' > "$d/docs/history/log.md"
}

# The citing file. `cite`/`shorthand`/`comma` build the tokens from pieces so
# this suite's own bytes carry no token the real gate would read as a cite.
cite()      { printf '%s:%s' "$1" "$2"; }
insert_after() {   # $1 = file, $2 = line number, $3 = text
  awk -v n="$2" -v t="$3" 'NR == n { print; print t; next } { print }' "$1" > "$1.new" &&
    mv "$1.new" "$1"
}
shorthand() { printf ':%s' "$1"; }
comma()     { printf ',%s' "$1"; }
set_notes() { printf '%s\n' "$1" > "$TREE/notes.md"; }

write_table() { PATHLINE_MIN_CITES=1 bash "$GUARD" --write "$TREE" "$TABLE" >/dev/null 2>&1 || true; }

run_gate() {
  local out rc
  out=$(PATHLINE_MIN_CITES="${MIN:-1}" bash "$GUARD" "$TREE" "$TABLE" 2>&1)
  rc=$?
  LAST_OUT=$out
  LAST_RC=$rc
}

TREE=""
TABLE=""
tmp=$(mktemp -d) || { printf 'FAIL  mktemp failed\n' >&2; exit 1; }
TREE="$tmp/tree"
TABLE="$TREE/scripts/tests/exp.txt"

hdr 'scenario 1 — a clean synthetic tree is green'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 2)")"
write_table
run_gate
if [ "$LAST_RC" -eq 0 ]; then
  ok 'clean tree: gate exited 0'
else
  bad "clean tree: gate exited $LAST_RC: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')"
fi
case $LAST_OUT in
  *'RESULT: 1 cite(s) checked, 0 violation(s)'*) ok 'clean tree: reports 1 cite checked and 0 violations' ;;
  *) bad "clean tree: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 2 — a one-line insert above a cited line reds'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 2)")"
write_table
printf 'inserted line\n' | cat - "$TREE/fx/anchor.rs" > "$TREE/fx/anchor.rs.new"
mv "$TREE/fx/anchor.rs.new" "$TREE/fx/anchor.rs"
run_gate
if [ "$LAST_RC" -ne 0 ]; then
  ok "one-line insert: gate exited $LAST_RC"
else
  bad 'one-line insert: gate exited 0 — a shifted cite was certified'
fi
case $LAST_OUT in
  *'notes.md:1 cites fx/anchor.rs:2'*) ok 'one-line insert: the failure names the citing file:line and the cite' ;;
  *) bad "one-line insert: failure does not name notes.md:1 and fx/anchor.rs:2: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
case $LAST_OUT in
  *'no longer carries the recorded text'*)
    ok 'one-line insert: the reason is the fingerprint, not arithmetic'
    printf 'witness M1: one-line insert reddened notes.md:1\n' ;;
  *) bad "one-line insert: unexpected reason: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 3 — a deleted cite reds'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 2)")"
write_table
printf 'nothing cited here\n' > "$TREE/notes.md"
run_gate
if [ "$LAST_RC" -ne 0 ]; then
  ok "deleted cite: gate exited $LAST_RC"
else
  bad 'deleted cite: gate exited 0 — a missing cite was certified'
fi
case $LAST_OUT in
  *'the expectation table records this cite but the tree does not carry it'*)
    ok 'deleted cite: named as a recorded-but-absent cite' ;;
  *) bad "deleted cite: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 4 — a renumbered cite reds'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 2)")"
write_table
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 3)")"
run_gate
if [ "$LAST_RC" -ne 0 ]; then
  ok "renumbered cite: gate exited $LAST_RC"
else
  bad 'renumbered cite: gate exited 0 — a moved number was certified'
fi
case $LAST_OUT in
  *'no expectation for this cite (added or renumbered)'*)
    ok 'renumbered cite: named as an unexpected cite' ;;
  *) bad "renumbered cite: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 5 — an absent expectation table is a hard failure'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 2)")"
rm -f "$TABLE"
run_gate
if [ "$LAST_RC" -ne 0 ]; then
  ok "absent table: gate exited $LAST_RC"
else
  bad 'absent table: gate exited 0 — a missing table was certified as clean'
fi
case $LAST_OUT in
  *'no expectation table to check cites against'*) ok 'absent table: named explicitly' ;;
  *) bad "absent table: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 6 — an empty expectation table is a hard failure'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 2)")"
mkdir -p "$(dirname -- "$TABLE")"
: > "$TABLE"
run_gate
if [ "$LAST_RC" -ne 0 ]; then
  ok "empty table: gate exited $LAST_RC"
else
  bad 'empty table: gate exited 0 — an empty table was certified as clean'
fi
case $LAST_OUT in
  *'carries no expectation'*) ok 'empty table: named explicitly' ;;
  *) bad "empty table: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 7 — a malformed record is a hard failure'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 2)")"
write_table
printf 'not\ta\trecord\n' >> "$TABLE"
run_gate
if [ "$LAST_RC" -ne 0 ]; then
  ok "malformed record: gate exited $LAST_RC"
else
  bad 'malformed record: gate exited 0 — an unparseable table was certified'
fi
case $LAST_OUT in
  *'record is not 9 tab-separated fields'*) ok 'malformed record: named explicitly' ;;
  *) bad "malformed record: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 8 — a cite past EOF reds'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 99)")"
write_table
run_gate
if [ "$LAST_RC" -ne 0 ]; then
  ok "past-EOF cite: gate exited $LAST_RC"
else
  bad 'past-EOF cite: gate exited 0'
fi
case $LAST_OUT in
  *'is past EOF'*) ok 'past-EOF cite: named with the EOF reason' ;;
  *) bad "past-EOF cite: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 9 — a cite to a blank line reds'
build_tree "$TREE"
printf 'one\n\ntwo\n' > "$TREE/fx/anchor.rs"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 2)")"
write_table
run_gate
if [ "$LAST_RC" -ne 0 ]; then
  ok "blank-line cite: gate exited $LAST_RC"
else
  bad 'blank-line cite: gate exited 0'
fi
case $LAST_OUT in
  *'the target line is blank'*) ok 'blank-line cite: named with the blank-line reason' ;;
  *) bad "blank-line cite: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 10 — the point-in-time set is excluded, as target and as source'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s and %s and %s -->' \
  "$(cite fx/anchor.rs 2)" "$(cite TODO.md 99)" "$(cite docs/history/log.md 99)")"
printf '<!-- %s -->\n' "$(cite fx/anchor.rs 99)" >> "$TREE/TODO.md"
write_table
run_gate
if [ "$LAST_RC" -eq 0 ]; then
  ok 'point-in-time: cites into TODO.md and docs/history are excluded, not red'
else
  bad "point-in-time: gate exited $LAST_RC: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')"
fi
case $LAST_OUT in
  *'RESULT: 1 cite(s) checked, 0 violation(s)'*) ok 'point-in-time: only the live cite is checked' ;;
  *) bad "point-in-time: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
case $LAST_OUT in
  *'2 cite(s) into the point-in-time set'*) ok 'point-in-time: the excluded count is reported, not dropped' ;;
  *) bad "point-in-time: the excluded count is not reported: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 11 — a shorthand moves independently of its anchor'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s and also %s -->' \
  "$(cite fx/anchor.rs 2)" "$(shorthand 4)")"
write_table
run_gate
if [ "$LAST_RC" -eq 0 ]; then
  ok 'shorthand: a same-line `:NNN` resolves to its anchor and is green'
else
  bad "shorthand: gate exited $LAST_RC: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')"
fi
case $LAST_OUT in
  *'RESULT: 2 cite(s) checked, 0 violation(s)'*) ok 'shorthand: counted as a cite of its own' ;;
  *) bad "shorthand: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
# (a) the shorthand's own target line shifts (the insert sits *below* the
# anchor's target, so only the shorthand's fingerprint changes): only the
# shorthand reds.
insert_after "$TREE/fx/anchor.rs" 2 'inserted'
run_gate
case $LAST_OUT in
  *'notes.md:1 cites :4'*) ok 'shorthand: a moved shorthand target reds the shorthand' ;;
  *) bad "shorthand: the moved target did not red the shorthand: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
case $LAST_OUT in
  *'RESULT: 2 cite(s) checked, 1 violation(s)'*) ok 'shorthand: exactly one violation (the anchor is untouched)' ;;
  *) bad "shorthand: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
# (b) the anchor's number moves while the shorthand's target does not.
build_tree "$TREE"
set_notes "$(printf '<!-- see %s and also %s -->' \
  "$(cite fx/anchor.rs 3)" "$(shorthand 4)")"
write_table
set_notes "$(printf '<!-- see %s and also %s -->' \
  "$(cite fx/anchor.rs 2)" "$(shorthand 4)")"
run_gate
case $LAST_OUT in
  *'notes.md:1 cites fx/anchor.rs:2'*) ok 'shorthand: a moved anchor reds the anchor' ;;
  *) bad "shorthand: the moved anchor did not red: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
case $LAST_OUT in
  *'notes.md:1 cites :4'*) bad 'shorthand: the untouched shorthand was reddened by the anchor move' ;;
  *) ok 'shorthand: the untouched shorthand stayed green' ;;
esac

hdr 'scenario 12 — an unanchored bare `:NNN` is prose, not a cite'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->\n\n<!-- the ratio 3%s4 and the port %s8080 are prose -->' \
  "$(cite fx/anchor.rs 2)" "$(shorthand '')" "$(shorthand '')")"
write_table
run_gate
if [ "$LAST_RC" -eq 0 ]; then
  ok 'unanchored: gate exited 0'
else
  bad "unanchored: gate exited $LAST_RC: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')"
fi
case $LAST_OUT in
  *'RESULT: 1 cite(s) checked, 0 violation(s)'*) ok 'unanchored: only the absolute cite is counted' ;;
  *) bad "unanchored: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 13 — a token naming a file this tree does not contain is out of tree'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s and the Go source %s -->' \
  "$(cite fx/anchor.rs 2)" "$(cite pkg/config/load.go 84)")"
write_table
run_gate
if [ "$LAST_RC" -eq 0 ]; then
  ok 'out of tree: gate exited 0'
else
  bad "out of tree: gate exited $LAST_RC: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')"
fi
case $LAST_OUT in
  *'RESULT: 1 cite(s) checked, 0 violation(s)'*) ok 'out of tree: not counted as a cite of this tree' ;;
  *) bad "out of tree: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
case $LAST_OUT in
  *'1 out-of-tree token(s)'*) ok 'out of tree: reported, not silently dropped' ;;
  *) bad "out of tree: the foreign count is not reported: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 14 — a `, N` continuation of a citation list is checked'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s%s -->' "$(cite fx/anchor.rs 2)" "$(comma ' 4')")"
write_table
run_gate
if [ "$LAST_RC" -eq 0 ]; then
  ok 'continuation: gate exited 0'
else
  bad "continuation: gate exited $LAST_RC: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')"
fi
case $LAST_OUT in
  *'RESULT: 2 cite(s) checked, 0 violation(s)'*) ok 'continuation: counted as a cite of its own' ;;
  *) bad "continuation: unexpected summary: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
insert_after "$TREE/fx/anchor.rs" 2 'inserted'
insert_after "$TREE/fx/anchor.rs" 3 'inserted'
run_gate
case $LAST_OUT in
  *'notes.md:1 cites 4'*) ok 'continuation: a moved continuation target reds it' ;;
  *) bad "continuation: the moved target did not red: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
# A comma that does not directly follow a citation is not a continuation.
build_tree "$TREE"
set_notes "$(printf '<!-- see %s%s -->' "$(cite fx/anchor.rs 2)" "$(comma ' a `[49]`')")"
write_table
run_gate
case $LAST_OUT in
  *'RESULT: 1 cite(s) checked, 0 violation(s)'*) ok 'continuation: a comma after prose does not cite a number' ;;
  *) bad "continuation: a prose comma was read as a cite: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 15 — an ambiguous path is reported and pinned'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/two_a/dup.rs 1)")"
printf '<!-- see %s -->\n' "$(cite dup.rs 1)" > "$TREE/notes2.md"
write_table
case $(cat "$TABLE") in
  *'ambiguous=1'*) ok 'ambiguous: the table pins the skip count' ;;
  *) bad "ambiguous: the table header does not pin the skip: $(head -1 "$TABLE")" ;;
esac
run_gate
case $LAST_OUT in
  *'1 ambiguous path(s) [pin 1]'*) ok 'ambiguous: reported with its pin' ;;
  *) bad "ambiguous: the skip is not reported: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
printf '<!-- see %s -->\n' "$(cite dup.rs 1)" >> "$TREE/notes.md"
run_gate
if [ "$LAST_RC" -ne 0 ]; then
  ok "ambiguous: a second ambiguous cite reds the pin (rc $LAST_RC)"
else
  bad 'ambiguous: a new unvalidatable cite was certified'
fi
case $LAST_OUT in
  *'ambiguous cite(s) (pinned 1)'*) ok 'ambiguous: the pin failure names the counts' ;;
  *) bad "ambiguous: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 16 — a weakly anchored cite is reported and pinned'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/repeat.rs 1)")"
write_table
run_gate
case $LAST_OUT in
  *'1 weakly anchored cite(s) [pin 1]'*) ok 'weak anchor: reported with its pin' ;;
  *) bad "weak anchor: the skip is not reported: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
printf '<!-- see %s -->\n' "$(cite fx/repeat.rs 2)" >> "$TREE/notes.md"
run_gate
if [ "$LAST_RC" -ne 0 ]; then
  ok "weak anchor: a second weak cite reds the pin (rc $LAST_RC)"
else
  bad 'weak anchor: a new weak cite was certified'
fi
case $LAST_OUT in
  *'weakly anchored cite(s) (pinned 1)'*) ok 'weak anchor: the pin failure names the counts' ;;
  *) bad "weak anchor: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 17 — the cite floor'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 2)")"
write_table
MIN=5 run_gate
if [ "$LAST_RC" -ne 0 ]; then
  ok "floor: a below-floor run exits $LAST_RC"
else
  bad 'floor: a below-floor run exited 0'
fi
case $LAST_OUT in
  *'only 1 cite(s) verified (floor 5)'*) ok 'floor: named with the measured and required counts' ;;
  *) bad "floor: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac
out=$(PATHLINE_MIN_CITES=0 bash "$GUARD" "$TREE" "$TABLE" 2>&1)
rc=$?
if [ "$rc" -ne 0 ]; then
  ok 'floor: a disabled floor is rejected'
else
  bad 'floor: a disabled floor was accepted'
fi
case $out in
  *'the cite floor is disabled'*) ok 'floor: the disabled floor names itself' ;;
  *) bad "floor: unexpected disabled-floor text: $(printf '%s' "$out" | tr '\n' ' ')" ;;
esac
out=$(PATHLINE_MIN_CITES=00 bash "$GUARD" "$TREE" "$TABLE" 2>&1)
rc=$?
case $out in
  *'the cite floor is disabled'*) ok 'floor: a zero-padded floor is rejected' ;;
  *) bad "floor: unexpected zero-padded-floor text: $(printf '%s' "$out" | tr '\n' ' ')" ;;
esac

hdr 'scenario 18 — the expectation table is never scanned as a citing file'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 2)")"
write_table
run_gate
case $LAST_OUT in
  *'RESULT: 1 cite(s) checked, 0 violation(s)'*)
    ok 'table exclusion: the raw tokens inside the table are not read as cites' ;;
  *) bad "table exclusion: the table was scanned: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'scenario 19 — --write is idempotent and reports its delta'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 2)")"
write_table
cp "$TABLE" "$tmp/first.txt"
write_table
if cmp -s "$tmp/first.txt" "$TABLE"; then
  ok 'write: a second --write is byte-identical'
else
  bad 'write: --write is not idempotent'
fi
write_out=$(PATHLINE_MIN_CITES=1 bash "$GUARD" --write "$TREE" "$TABLE" 2>&1)
case $write_out in
  *'0 added, 0 removed'*) ok 'write: the delta against the previous table is reported' ;;
  *) bad "write: unexpected delta line: $(printf '%s' "$write_out" | tr '\n' ' ')" ;;
esac
printf '<!-- see %s -->\n' "$(cite fx/anchor.rs 3)" >> "$TREE/notes.md"
write_out=$(PATHLINE_MIN_CITES=1 bash "$GUARD" --write "$TREE" "$TABLE" 2>&1)
case $write_out in
  *'1 added, 0 removed'*) ok 'write: an added cite shows as one added record' ;;
  *) bad "write: unexpected delta after adding a cite: $(printf '%s' "$write_out" | tr '\n' ' ')" ;;
esac

hdr 'scenario 20 — a failing git ls-files is a hard failure'
build_tree "$TREE"
set_notes "$(printf '<!-- see %s -->' "$(cite fx/anchor.rs 2)")"
write_table
printf 'not a git directory\n' > "$TREE/.git"
run_gate
if [ "$LAST_RC" -ne 0 ]; then
  ok "git failure: gate exited $LAST_RC"
else
  bad 'git failure: gate exited 0 on a tree whose index cannot be read'
fi
case $LAST_OUT in
  *'git ls-files failed'*) ok 'git failure: named as a partial tree' ;;
  *) bad "git failure: unexpected failure text: $(printf '%s' "$LAST_OUT" | tr '\n' ' ')" ;;
esac

hdr 'summary'
if [ "$fails" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
else
  printf 'RESULT: %d fixture check(s), %d failure(s) above\n' "$checks" "$fails"
fi
exit "$fails"
