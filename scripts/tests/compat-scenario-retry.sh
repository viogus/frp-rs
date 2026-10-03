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
# The classification rule this pins (review round 1, finding A1): a
# `FAIL:<class>` verdict is refused **wherever it appears** except a bare or
# labelled `FAIL:CONNECT_TIMEOUT`/`FAIL:TIMEOUT`, so a `FAIL:MISMATCH` whose
# payload *quotes* "not reachable" is not re-driven; and the prose readiness
# phrases are end-anchored, so a message that merely mentions unreachability
# mid-string is not either.
#
# Scenarios (the classification table is thirteen checks; the rest are one each):
#   1..13 classification: prose readiness gates (`not reachable`, `did not
#         start`, `not listening`, with and without a trailing parenthetical)
#         and the two timeout verdicts are re-drivable; a `FAIL:MISMATCH` whose
#         payload quotes "not reachable", a `FAIL:CONNECT_RESPONSE`, a
#         mid-string mention of unreachability and other assertions are not.
#   14    a readiness failure that does not recur: 2 attempts, 1 passed,
#         0 failed, RETRIED_PASS=1 and no leftover failure record.
#   15    a readiness failure that recurs on the clean re-drive: bounded to
#         2 attempts and reported exactly once — the bound, and no double count.
#   16    the adversarial case end-to-end: a scenario failing with
#         `FAIL:MISMATCH expected='proxy port 1 not reachable'` is **not**
#         re-driven — 1 attempt, 1 failure, RETRIED_PASS=0.
#   17    FAIL:CONNECT_RESPONSE is never re-driven.
#   18    FAIL:CONNECT_TIMEOUT is still re-driven and absorbed.
#   19    FAIL:TIMEOUT is still re-driven and absorbed.
#   20    FRP_COMPAT_RETRY_MAX=0 disables the re-drive.
#   21    a clean pass runs once and is not marked as retried.
#   22    a withdrawn attempt's `pass_test` is withdrawn with it (no double
#         count on PASS).
#   23    an attempt with *any* non-readiness failure among its reasons is not
#         re-driven, even when another reason is readiness-class.
#   24    the harness refuses a non-numeric `FRP_COMPAT_RETRY_MAX` up front,
#         driving the real file rather than an extraction.
#   25    the harness refuses a value over the hard cap up front, too.
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
MIN_CHECKS=25

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
RETRY_MAX_CAP=5
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
yes|proxy port 22335 not reachable (auth rejection false positive?)
yes|Rust frps did not start
yes|Go frps did not start
yes|Go frps WSS port 22001 not listening
yes|FAIL:CONNECT_TIMEOUT
yes|FAIL:TIMEOUT
no|FAIL:MISMATCH expected='proxy port 1 not reachable' got='b'
no|FAIL:CONNECT_RESPONSE b'CONNECT x:22 HTTP/1.1\r\n'
no|peer answered: not reachable
no|expected SSH banner starting with 'SSH-', got: BANNER_ERROR
CASES

# 14. readiness failure, clean on the re-drive.
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

# 15. readiness failure on both attempts: bounded, reported once.
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

# 16. review round 1, A1: a deterministic MISMATCH whose payload quotes the
#     retryable phrase must not be re-driven, and must not be counted twice.
scn_mismatch_quoting_readiness() {
  ATTEMPTS=$((ATTEMPTS + 1))
  fail_test mismatch "FAIL:MISMATCH expected='proxy port 1 not reachable' got='b'"
}
reset_run 1
run_test scn_mismatch_quoting_readiness >/dev/null 2>&1
if [ "$ATTEMPTS" = 1 ] && [ "$FAIL" = 1 ] && [ "$PASS" = 0 ] &&
   [ "$RETRIED_PASS" = 0 ] && [ "${#FAILURES[@]}" = 1 ]; then
  ok "a MISMATCH quoting 'not reachable' is not re-driven: 1 attempt, 1 failure"
else
  bad "MISMATCH quoting readiness was re-driven (attempts=$ATTEMPTS pass=$PASS fail=$FAIL retried=$RETRIED_PASS)!"
fi

# 17. a live peer's CONNECT answer is never re-driven.
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

# 18. FAIL:CONNECT_TIMEOUT is still the retryable class.
scn_connect_timeout() {
  ATTEMPTS=$((ATTEMPTS + 1))
  if (( ATTEMPTS == 1 )); then
    fail_test connect-timeout "FAIL:CONNECT_TIMEOUT"
  else
    pass_test connect-timeout
  fi
}
reset_run 1
run_test scn_connect_timeout >/dev/null 2>&1
if [ "$ATTEMPTS" = 2 ] && [ "$PASS" = 1 ] && [ "$FAIL" = 0 ] && [ "$RETRIED_PASS" = 1 ]; then
  ok 'FAIL:CONNECT_TIMEOUT is still re-driven and absorbed'
else
  bad "FAIL:CONNECT_TIMEOUT (attempts=$ATTEMPTS pass=$PASS fail=$FAIL retried=$RETRIED_PASS)"
fi

# 19. FAIL:TIMEOUT is still the retryable class.
scn_timeout() {
  ATTEMPTS=$((ATTEMPTS + 1))
  if (( ATTEMPTS == 1 )); then
    fail_test timeout "FAIL:TIMEOUT"
  else
    pass_test timeout
  fi
}
reset_run 1
run_test scn_timeout >/dev/null 2>&1
if [ "$ATTEMPTS" = 2 ] && [ "$PASS" = 1 ] && [ "$FAIL" = 0 ] && [ "$RETRIED_PASS" = 1 ]; then
  ok 'FAIL:TIMEOUT is still re-driven and absorbed'
else
  bad "FAIL:TIMEOUT (attempts=$ATTEMPTS pass=$PASS fail=$FAIL retried=$RETRIED_PASS)"
fi

# 20. the bound is a knob: 0 disables the re-drive.
reset_run 0
run_test scn_late_once >/dev/null 2>&1
if [ "$ATTEMPTS" = 1 ] && [ "$FAIL" = 1 ] && [ "$RETRIED_PASS" = 0 ]; then
  ok 'FRP_COMPAT_RETRY_MAX=0 disables the re-drive: 1 attempt, 1 failure'
else
  bad "RETRY_MAX=0 (attempts=$ATTEMPTS fail=$FAIL)"
fi

# 21. a clean pass is untouched.
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

# 22. a withdrawn attempt's pass is withdrawn with it. The synthetic scenario
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

# 23. one readiness reason among several, one of them a protocol answer: no
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

# 24. a non-numeric bound is refused before it can reach `(( ))`. This drives
#     the real file, not an extraction: the guard sits between arg parsing and
#     the binary checks, so no Go frp and no Rust build are needed.
bad_rc=0
bad_out=$(FRP_COMPAT_RETRY_MAX='seven' bash "$COMPAT" 2>&1) || bad_rc=$?
case "$bad_out" in
  *"FRP_COMPAT_RETRY_MAX must be a non-negative integer"*) bad_msg=1 ;;
  *) bad_msg=0 ;;
esac
if [ "$bad_rc" = 2 ] && [ "$bad_msg" = 1 ]; then
  ok 'a non-numeric FRP_COMPAT_RETRY_MAX exits 2 and names the variable'
else
  bad "non-numeric FRP_COMPAT_RETRY_MAX (rc=$bad_rc, message $( [ "$bad_msg" = 1 ] && echo present || echo missing ))"
fi

# 25. review round 1, A4: the knob has a hard ceiling, so a large value cannot
#     turn a red run into a long (or cancelled) one. Also drives the real file.
cap_rc=0
cap_out=$(FRP_COMPAT_RETRY_MAX="$((RETRY_MAX_CAP + 1))" bash "$COMPAT" 2>&1) || cap_rc=$?
case "$cap_out" in
  *"FRP_COMPAT_RETRY_MAX must be <= $RETRY_MAX_CAP"*) cap_msg=1 ;;
  *) cap_msg=0 ;;
esac
if [ "$cap_rc" = 2 ] && [ "$cap_msg" = 1 ]; then
  ok "a FRP_COMPAT_RETRY_MAX above the cap ($RETRY_MAX_CAP) exits 2 and names the cap"
else
  bad "over-cap FRP_COMPAT_RETRY_MAX (rc=$cap_rc, message $( [ "$cap_msg" = 1 ] && echo present || echo missing ))"
fi
