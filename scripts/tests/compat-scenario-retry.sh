#!/usr/bin/env bash
# compat-scenario-retry.sh — fixture checks for the bounded re-drive of a
# readiness-class scenario failure in `scripts/compat-test.sh`.
#
# Why this exists: the re-drive converts a red attempt into a green run, so
# everything standing between "a transient readiness failure is absorbed" and
# "a real regression is re-run until it passes" is the *classification*, the
# *bound* and the *bookkeeping*. None of the three is observable from a green
# CI run — the first two are invisible when nothing flakes, and the third is
# invisible when nothing is withdrawn. They are drivable here in about a second,
# with no network, no Go frp and no repo build.
#
# How: `is_readiness_failure`, `pass_test`, `fail_test` and `run_test` are
# sed-extracted **verbatim** from `scripts/compat-test.sh` and driven against
# synthetic scenarios that call the real `pass_test`/`fail_test`, so the
# counters, the failure ledger and the withdrawal are the shipped ones. Each
# extraction is asserted (`command -v`), so a renamed or reshaped function reds
# here instead of silently testing nothing — a fixture whose subject vanished
# must not pass vacuously.
#
# Scenarios (the classification table is ten checks; the rest are one each):
#   1..10 classification: readiness/timeout reasons are re-drivable; a protocol
#         answer from a live peer (MISMATCH, CONNECT_RESPONSE) and any other
#         assertion are not.
#   11    a readiness failure that does not recur: 2 attempts, 1 passed,
#         0 failed, RETRIED_PASS=1 and no leftover failure record.
#   12    a readiness failure that recurs on the clean re-drive: bounded to
#         2 attempts and reported exactly once — the bound, and no double count.
#   13    FAIL:MISMATCH is never re-driven.
#   14    FAIL:CONNECT_RESPONSE is never re-driven.
#   15    FRP_COMPAT_RETRY_MAX=0 disables the re-drive.
#   16    a clean pass runs once and is not marked as retried.
#   17    a withdrawn attempt's `pass_test` is withdrawn with it (no double
#         count on PASS).
#   18    an attempt with *any* non-readiness failure among its reasons is not
#         re-driven, even when another reason is readiness-class.
#   19    the harness refuses a non-numeric `FRP_COMPAT_RETRY_MAX` up front,
#         driving the real file rather than an extraction.
#
# Residue, declared rather than denied: `scripts/compat-test.sh` is unpinned
# (the port-ownership step records the same for its structural probes), so a
# hostile edit to the harness could neuter both the function under test and this
# extraction. This suite pins the *semantics* the shipped text has, not the text
# itself; the outer pin that makes weakening it visible belongs to whichever
# `ci.yml` step runs this file.
#
# Usage: bash scripts/tests/compat-scenario-retry.sh
set -uo pipefail

self=${BASH_SOURCE[0]:-$0}
case "$self" in
  */*) ;;
  *) if [ -e "$self" ]; then self=$PWD/$self; else self=$(command -v -- "$self") || {
       printf 'FAIL  cannot locate the fixture: %s\n' "$0"; exit 1; }; fi ;;
esac
ROOT=$(cd -P -- "$(dirname -- "$self")/../.." && pwd)
COMPAT="$ROOT/scripts/compat-test.sh"

checks=0
fails=0
# Pinned total: `exit "$fails"` alone is happy with a suite that silently stops
# checking, so the floor is enforced from the exit trap on every path.
MIN_CHECKS=19

ok()  { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf '  FAIL  %s\n' "$1"; }

cleanup_all() {
  local rc=$?
  if [ "$rc" -eq 0 ] && [ "$fails" -gt 0 ]; then
    rc=1
  fi
  if [ "$rc" -eq 0 ]; then
    case ${MIN_CHECKS:-} in
      ''|0) printf 'FAIL  the check floor is disabled (MIN_CHECKS=%s); the suite cannot vouch for itself\n' \
              "${MIN_CHECKS:-<unset>}" >&2; rc=1 ;;
      *[!0-9]*) printf 'FAIL  the check floor is not a number (MIN_CHECKS=%s)\n' "$MIN_CHECKS" >&2; rc=1 ;;
      *)
        if [ "$checks" -lt "$MIN_CHECKS" ]; then
          printf 'FAIL  suite exited 0 after only %s check(s); expected at least %s — scenarios did not run\n' \
            "$checks" "$MIN_CHECKS" >&2
          rc=1
        fi ;;
    esac
  fi
  if [ "$rc" -eq 0 ]; then
    printf '\nRESULT: %d fixture check(s) hold\n' "$checks"
  else
    printf '\nRESULT: %d fixture check(s), %d failure(s) above\n' "$checks" "$fails"
  fi
  exit "$rc"
}
trap cleanup_all EXIT

[ -f "$COMPAT" ] || { printf 'FAIL  harness not found: %s\n' "$COMPAT"; exit 1; }

# --- the globals `run_test` / `fail_test` read -------------------------------
PASS=0
FAIL=0
FAILURES=()
RETRY_MAX=1
RETRIED_PASS=0
_ATTEMPT_FAILURES=()
CI=false
VERBOSE=false
DEBUG=false
RED=''; GREEN=''; YELLOW=''; NC=''
TEST_DIR="${TMPDIR:-/tmp}/compat-scenario-retry.$$"
mkdir -p "$TEST_DIR" || { printf 'FAIL  cannot create %s\n' "$TEST_DIR"; exit 1; }
ATTEMPTS=0
# The parts of the harness `run_test` reaches that this fixture does not test:
# the log line, the pid reaping and the stray sweep.
log() { :; }
cleanup_pids() { :; }
reap_scoped_strays() { :; }

# --- extract the functions under test, verbatim ------------------------------
for fn in is_readiness_failure pass_test fail_test run_test; do
  body=$(sed -n "/^$fn()/,/^}/p" "$COMPAT")
  [ -n "$body" ] || { printf 'FAIL  %s() is not extractable from %s\n' "$fn" "$COMPAT" >&2; exit 1; }
  eval "$body"
  command -v "$fn" >/dev/null || { printf 'FAIL  extracted %s is not defined\n' "$fn" >&2; exit 1; }
done

reset_run() {
  PASS=0
  FAIL=0
  FAILURES=()
  RETRY_MAX="${1:-1}"
  RETRIED_PASS=0
  _ATTEMPT_FAILURES=()
  ATTEMPTS=0
}

# --- classification ----------------------------------------------------------
while IFS='|' read -r want reason; do
  if is_readiness_failure "$reason"; then got=yes; else got=no; fi
  if [ "$got" = "$want" ]; then
    ok "classify($want): $reason"
  else
    bad "classify: '$reason' -> $got, wanted $want"
  fi
done <<'CASES'
yes|proxy port 20403 not reachable
yes|tcpmux port 22001 not reachable
yes|VHost HTTP port 19286 not reachable
yes|Rust frps did not start
yes|Go frps did not start
yes|FAIL:CONNECT_TIMEOUT
yes|FAIL:TIMEOUT
no|FAIL:MISMATCH expected='a' got='b'
no|FAIL:CONNECT_RESPONSE b'CONNECT x:22 HTTP/1.1\r\n'
no|expected SSH banner starting with 'SSH-', got: BANNER_ERROR
CASES

# 11. readiness failure, clean on the re-drive.
scn_late_once() {
  ATTEMPTS=$((ATTEMPTS + 1))
  if (( ATTEMPTS == 1 )); then
    fail_test late-once "proxy port 1 not reachable"
  else
    pass_test late-once
  fi
}
reset_run 1
run_test scn_late_once >/dev/null 2>&1
if [ "$ATTEMPTS" = 2 ] && [ "$PASS" = 1 ] && [ "$FAIL" = 0 ] &&
   [ "$RETRIED_PASS" = 1 ] && [ "${#FAILURES[@]}" = 0 ]; then
  ok 'a readiness failure with a clean re-drive: 2 attempts, 1 passed, 0 failed, RETRIED_PASS=1'
else
  bad "readiness re-drive bookkeeping (attempts=$ATTEMPTS pass=$PASS fail=$FAIL retried=$RETRIED_PASS failures=${#FAILURES[@]})"
fi

# 12. readiness failure on both attempts: bounded, reported once.
scn_late_always() {
  ATTEMPTS=$((ATTEMPTS + 1))
  fail_test late-always "proxy port 1 not reachable"
}
reset_run 1
run_test scn_late_always >/dev/null 2>&1
if [ "$ATTEMPTS" = 2 ] && [ "$FAIL" = 1 ] && [ "$PASS" = 0 ] &&
   [ "$RETRIED_PASS" = 0 ] && [ "${#FAILURES[@]}" = 1 ]; then
  ok 'a recurring readiness failure: bounded to 2 attempts, exactly 1 recorded failure'
else
  bad "recurring readiness failure (attempts=$ATTEMPTS pass=$PASS fail=$FAIL failures=${#FAILURES[@]})"
fi

# 13. a protocol assertion is never re-driven.
scn_mismatch() {
  ATTEMPTS=$((ATTEMPTS + 1))
  fail_test mismatch "FAIL:MISMATCH expected='a' got='b'"
}
reset_run 1
run_test scn_mismatch >/dev/null 2>&1
if [ "$ATTEMPTS" = 1 ] && [ "$FAIL" = 1 ] && [ "$RETRIED_PASS" = 0 ]; then
  ok 'FAIL:MISMATCH is not re-driven: 1 attempt'
else
  bad "MISMATCH re-driven (attempts=$ATTEMPTS fail=$FAIL)"
fi

# 14. a live peer's CONNECT answer is never re-driven.
scn_connectres() {
  ATTEMPTS=$((ATTEMPTS + 1))
  fail_test connres "FAIL:CONNECT_RESPONSE b'CONNECT x:22 HTTP/1.1'"
}
reset_run 1
run_test scn_connectres >/dev/null 2>&1
if [ "$ATTEMPTS" = 1 ]; then
  ok 'FAIL:CONNECT_RESPONSE is not re-driven: 1 attempt'
else
  bad "CONNECT_RESPONSE re-driven ($ATTEMPTS attempts)"
fi

# 15. the bound is a knob: 0 disables the re-drive.
reset_run 0
run_test scn_late_once >/dev/null 2>&1
if [ "$ATTEMPTS" = 1 ] && [ "$FAIL" = 1 ] && [ "$RETRIED_PASS" = 0 ]; then
  ok 'FRP_COMPAT_RETRY_MAX=0 disables the re-drive: 1 attempt, 1 failure'
else
  bad "RETRY_MAX=0 (attempts=$ATTEMPTS fail=$FAIL)"
fi

# 16. a clean pass is untouched.
scn_clean() {
  ATTEMPTS=$((ATTEMPTS + 1))
  pass_test clean
}
reset_run 1
run_test scn_clean >/dev/null 2>&1
if [ "$ATTEMPTS" = 1 ] && [ "$PASS" = 1 ] && [ "$RETRIED_PASS" = 0 ]; then
  ok 'a clean pass runs once and is not marked as retried'
else
  bad "clean pass (attempts=$ATTEMPTS pass=$PASS retried=$RETRIED_PASS)"
fi

# 17. a withdrawn attempt's pass is withdrawn with it. The synthetic scenario
#     mirrors a real one: mutually exclusive branches per attempt.
scn_pass_then_late() {
  ATTEMPTS=$((ATTEMPTS + 1))
  if (( ATTEMPTS == 1 )); then
    pass_test part
    fail_test part "proxy port 1 not reachable"
  else
    pass_test part
  fi
}
reset_run 1
run_test scn_pass_then_late >/dev/null 2>&1
if [ "$ATTEMPTS" = 2 ] && [ "$PASS" = 1 ] && [ "$FAIL" = 0 ]; then
  ok "a withdrawn attempt's pass is withdrawn too: PASS=1 after the re-drive"
else
  bad "withdrawn pass double counted (attempts=$ATTEMPTS pass=$PASS fail=$FAIL)"
fi

# 18. one readiness reason among several, one of them a protocol answer: no
#     re-drive at all — the class check is "every reason", not "any reason".
scn_mixed() {
  ATTEMPTS=$((ATTEMPTS + 1))
  fail_test mixed "proxy port 1 not reachable"
  fail_test mixed "FAIL:MISMATCH expected='a' got='b'"
}
reset_run 1
run_test scn_mixed >/dev/null 2>&1
if [ "$ATTEMPTS" = 1 ] && [ "$FAIL" = 2 ]; then
  ok 'an attempt with any non-readiness failure is not re-driven'
else
  bad "mixed failure re-driven (attempts=$ATTEMPTS fail=$FAIL)"
fi

# 19. a non-numeric bound is refused before it can reach `(( ))`. This drives
#     the real file, not an extraction: the guard sits between arg parsing and
#     the binary checks, so no Go frp and no Rust build are needed.
bad_missing=0
bad_out=$(FRP_COMPAT_RETRY_MAX='seven' bash "$COMPAT" 2>&1) || bad_rc=$?
bad_rc=${bad_rc:-0}
case "$bad_out" in
  *"FRP_COMPAT_RETRY_MAX must be a non-negative integer"*) bad_missing=1 ;;
esac
if [ "$bad_rc" = 2 ] && [ "$bad_missing" = 1 ]; then
  ok 'a non-numeric FRP_COMPAT_RETRY_MAX exits 2 and names the variable'
else
  bad "non-numeric FRP_COMPAT_RETRY_MAX (rc=$bad_rc, message $( [ "$bad_missing" = 1 ] && echo present || echo missing ))"
fi
