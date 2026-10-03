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
# must not pass vacuously. The knob's own validation is not extractable (it runs
# at load), so those checks drive the real file with a hostile `GO_FRP_DIR` that
# stops it at the binary check.
#
# The classification rule this pins (review round 1 A1 + round 2 D2-F3, in this
# order): a reason carrying `FAIL:MISMATCH`/`FAIL:CONNECT_RESPONSE` anywhere is
# refused first — even beside a genuine timeout from the other proxy; then a
# wrapped or bare `FAIL:CONNECT_TIMEOUT`/`FAIL:TIMEOUT` is retryable and any
# other `FAIL:` class is refused; and the prose readiness phrases are
# end-anchored and port-qualified, so a message that merely mentions
# unreachability is refused.
#
# Scenarios (the classification table is eighteen checks; the rest are one each):
#   1..18 classification: prose readiness gates (with and without the auth-reject
#         suffix), the two timeout verdicts bare/labelled/wrapped, and the
#         refusals — a `FAIL:MISMATCH` quoting "not reachable", the same beside a
#         timeout, a `FAIL:CONNECT_RESPONSE`, a mid-string mention and other
#         assertions.
#   19    a readiness failure that does not recur: 2 attempts, 1 passed,
#         0 failed, RETRIED_PASS=1 and no leftover failure record.
#   20    a readiness failure that recurs on the clean re-drive: bounded to
#         2 attempts and reported exactly once — the bound, and no double count.
#   21    the round-1 A1 case end-to-end: a scenario failing with
#         `FAIL:MISMATCH expected='proxy port 1 not reachable'` is **not**
#         re-driven — 1 attempt, 1 failure, RETRIED_PASS=0.
#   22    FAIL:CONNECT_RESPONSE is never re-driven.
#   23    FAIL:CONNECT_TIMEOUT is still re-driven and absorbed.
#   24    FAIL:TIMEOUT is still re-driven and absorbed.
#   25    round-2 D2-F3: a *wrapped* timeout verdict (`expected OK: got
#         FAIL:TIMEOUT`) is still re-driven.
#   26    FRP_COMPAT_RETRY_MAX=0 disables the re-drive.
#   27    a clean pass runs once and is not marked as retried.
#   28    a withdrawn attempt's `pass_test` is withdrawn with it (no double
#         count on PASS).
#   29    an attempt with *any* non-readiness failure among its reasons is not
#         re-driven, even when another reason is readiness-class.
#   30    the harness refuses a non-numeric `FRP_COMPAT_RETRY_MAX` up front.
#   31    the harness refuses a value over the hard cap up front.
#   32    round-2 D2-F2: a zero-padded `08` is refused, not read as octal.
#   33    the same hole with more padding (`0008`) is refused too.
#   34    a padded value that is *under* the cap (`05`) is accepted, so the
#         stripping does not over-reject.
#   35    round-3 F-D3-2: `FRP_COMPAT_READY_MIN=abc` is refused at load, naming
#         the variable.
#   36    the readiness floor survives zero padding: `FRP_COMPAT_READY_MIN=08` is
#         applied as decimal 8 by the gate, not read as octal and dropped.
#   37    a valid floor is actually used: the gate hands the ownership wait the
#         floor value when the caller's timeout is smaller.
#   38    the gate refuses a non-decimal floor itself, instead of letting `(( ))`
#         abort — fails closed, with the variable named.
#   39    round-3 audit: `--shard 0/0` is refused at load rather than becoming a
#         division by zero (and `0/08` is normalised to a decimal `0/8`) in the
#         XTCP shard arithmetic, which otherwise runs nothing and reports zero
#         tests as a success.
#   40    a non-decimal `--shard` (1/x) is refused at load too.
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
MIN_CHECKS=40

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
for fn in is_readiness_failure pass_test fail_test run_test wait_for_port_safe; do
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

# The knob's validation runs at load, so it cannot be extracted; drive the real
# file with a Go directory that cannot exist, so a run that gets past the
# validation stops at the binary check instead of starting the suite.
run_harness_with_env() {
  env GO_FRP_DIR=/nonexistent-frp-fixture GO_FRP_VERSION=0.0.0-fixture \
    "$@" bash "$COMPAT" 2>&1
}
run_harness_with_retry_max() { run_harness_with_env "FRP_COMPAT_RETRY_MAX=$1"; }
run_harness_args() {   # args passed straight through to the harness
  env GO_FRP_DIR=/nonexistent-frp-fixture GO_FRP_VERSION=0.0.0-fixture \
    bash "$COMPAT" "$@" 2>&1
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
yes|tcp: FAIL:CONNECT_TIMEOUT
yes|expected OK: got FAIL:TIMEOUT
yes|proxy1=FAIL:TIMEOUT proxy2=FAIL:CONNECT_TIMEOUT
no|FAIL:MISMATCH expected='proxy port 1 not reachable' got='b'
no|FAIL:CONNECT_RESPONSE b'CONNECT x:22 HTTP/1.1\r\n'
no|expected OK: got FAIL:MISMATCH expected='a' got='b'
no|proxy1=FAIL:MISMATCH expected='a' got='b' proxy2=FAIL:TIMEOUT
no|peer answered: not reachable
no|expected SSH banner starting with 'SSH-', got: BANNER_ERROR
CASES

# 19. readiness failure, clean on the re-drive.
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

# 20. readiness failure on both attempts: bounded, reported once.
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

# 21. review round 1, A1: a deterministic MISMATCH whose payload quotes the
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

# 22. a live peer's CONNECT answer is never re-driven.
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

# 23. FAIL:CONNECT_TIMEOUT is still the retryable class.
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

# 24. FAIL:TIMEOUT is still the retryable class.
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

# 25. review round 2, D2-F3: the two wrapping call sites build
#     `expected OK: got $result`, so a genuine timeout arrives embedded in a
#     longer reason and must still be re-driven.
scn_wrapped_timeout() {
  ATTEMPTS=$((ATTEMPTS + 1))
  if (( ATTEMPTS == 1 )); then
    fail_test wrapped-timeout "expected OK: got FAIL:TIMEOUT"
  else
    pass_test wrapped-timeout
  fi
}
reset_run 1
run_test scn_wrapped_timeout >/dev/null 2>&1
if [ "$ATTEMPTS" = 2 ] && [ "$PASS" = 1 ] && [ "$FAIL" = 0 ] && [ "$RETRIED_PASS" = 1 ]; then
  ok 'a wrapped timeout verdict is still re-driven and absorbed'
else
  bad "wrapped FAIL:TIMEOUT (attempts=$ATTEMPTS pass=$PASS fail=$FAIL retried=$RETRIED_PASS)"
fi

# 26. the bound is a knob: 0 disables the re-drive.
reset_run 0
run_test scn_late_once >/dev/null 2>&1
if [ "$ATTEMPTS" = 1 ] && [ "$FAIL" = 1 ] && [ "$RETRIED_PASS" = 0 ]; then
  ok 'FRP_COMPAT_RETRY_MAX=0 disables the re-drive: 1 attempt, 1 failure'
else
  bad "RETRY_MAX=0 (attempts=$ATTEMPTS fail=$FAIL)"
fi

# 27. a clean pass is untouched.
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

# 28. a withdrawn attempt's pass is withdrawn with it. The synthetic scenario
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

# 29. one readiness reason among several, one of them a protocol answer: no
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

# 30. a non-numeric bound is refused before it can reach `(( ))`.
bad_rc=0
bad_out=$(run_harness_with_retry_max 'seven') || bad_rc=$?
case "$bad_out" in
  *"FRP_COMPAT_RETRY_MAX must be a non-negative integer"*) bad_msg=1 ;;
  *) bad_msg=0 ;;
esac
if [ "$bad_rc" = 2 ] && [ "$bad_msg" = 1 ]; then
  ok 'a non-numeric FRP_COMPAT_RETRY_MAX exits 2 and names the variable'
else
  bad "non-numeric FRP_COMPAT_RETRY_MAX (rc=$bad_rc, message $( [ "$bad_msg" = 1 ] && echo present || echo missing ))"
fi

# 31. review round 1, A4: the knob has a hard ceiling.
cap_rc=0
cap_out=$(run_harness_with_retry_max "$((RETRY_MAX_CAP + 1))") || cap_rc=$?
case "$cap_out" in
  *"FRP_COMPAT_RETRY_MAX must be <= $RETRY_MAX_CAP"*) cap_msg=1 ;;
  *) cap_msg=0 ;;
esac
if [ "$cap_rc" = 2 ] && [ "$cap_msg" = 1 ]; then
  ok "a FRP_COMPAT_RETRY_MAX above the cap ($RETRY_MAX_CAP) exits 2 and names the cap"
else
  bad "over-cap FRP_COMPAT_RETRY_MAX (rc=$cap_rc, message $( [ "$cap_msg" = 1 ] && echo present || echo missing ))"
fi

# 32. review round 2, D2-F2: `08` is digits-only, so the spelling check used to
#     accept it — and `(( ))` then read it as octal, making the cap comparison a
#     false condition instead of an abort. It must be refused like any other
#     over-cap value.
zero_rc=0
zero_out=$(run_harness_with_retry_max '08') || zero_rc=$?
case "$zero_out" in
  *"FRP_COMPAT_RETRY_MAX must be <= $RETRY_MAX_CAP"*) zero_msg=1 ;;
  *) zero_msg=0 ;;
esac
if [ "$zero_rc" = 2 ] && [ "$zero_msg" = 1 ]; then
  ok 'a zero-padded over-cap value (08) exits 2 and names the cap'
else
  bad "zero-padded 08 (rc=$zero_rc, message $( [ "$zero_msg" = 1 ] && echo present || echo missing ))"
fi

# 33. the same hole with more padding.
pad_rc=0
pad_out=$(run_harness_with_retry_max '0008') || pad_rc=$?
case "$pad_out" in
  *"FRP_COMPAT_RETRY_MAX must be <= $RETRY_MAX_CAP"*) pad_msg=1 ;;
  *) pad_msg=0 ;;
esac
if [ "$pad_rc" = 2 ] && [ "$pad_msg" = 1 ]; then
  ok 'a longer zero-padded over-cap value (0008) is refused too'
else
  bad "zero-padded 0008 (rc=$pad_rc, message $( [ "$pad_msg" = 1 ] && echo present || echo missing ))"
fi

# 34. a padded value under the cap is *accepted* (it gets past validation to the
#     binary check), so the stripping does not over-reject.
ok_rc=0
ok_out=$(run_harness_with_retry_max '05') || ok_rc=$?
case "$ok_out" in
  *"FRP_COMPAT_RETRY_MAX must be"*) ok_refused=1 ;;
  *) ok_refused=0 ;;
esac
if [ "$ok_rc" != 2 ] && [ "$ok_refused" = 0 ]; then
  ok 'a zero-padded under-cap value (05) passes validation and reaches the binary check'
else
  bad "zero-padded 05 was refused (rc=$ok_rc, refusal message $( [ "$ok_refused" = 1 ] && echo present || echo absent ))"
fi

# --- the readiness floor (review round 3, F-D3-2) ----------------------------
# `wait_for_port_safe` is the only consumer of `FRP_COMPAT_READY_MIN`, so drive
# the extracted gate against a stub ownership wait that records the timeout it is
# handed. `08` is the adversarial value: `(( timeout < 08 ))` is a bash syntax
# error, which reads false and silently drops the floor.
WAIT_SEEN=""
cpo_wait_port_ready() { WAIT_SEEN="$2"; return 1; }
gate_with_floor() {  # $1 = FRP_COMPAT_READY_MIN, $2 = caller timeout
  WAIT_SEEN=""
  FRP_COMPAT_READY_MIN="$1" wait_for_port_safe 127.0.0.1 1 "$2" >/dev/null 2>&1
}

# 35. a non-decimal floor is refused at load, naming the variable.
floor_rc=0
floor_out=$(run_harness_with_env 'FRP_COMPAT_READY_MIN=abc') || floor_rc=$?
case "$floor_out" in
  *"FRP_COMPAT_READY_MIN must be a non-negative integer"*) floor_msg=1 ;;
  *) floor_msg=0 ;;
esac
if [ "$floor_rc" = 2 ] && [ "$floor_msg" = 1 ]; then
  ok 'a non-numeric FRP_COMPAT_READY_MIN exits 2 and names the variable'
else
  bad "non-numeric FRP_COMPAT_READY_MIN (rc=$floor_rc, message $( [ "$floor_msg" = 1 ] && echo present || echo missing ))"
fi

# 36. the floor survives zero padding: `08` is decimal 8 here, not an octal
#     syntax error that leaves the caller's shorter timeout in place.
gate_with_floor '08' 1
if [ "$WAIT_SEEN" = 8 ]; then
  ok 'a zero-padded FRP_COMPAT_READY_MIN (08) floors the gate to decimal 8'
else
  bad "zero-padded readiness floor: the gate handed the ownership wait '${WAIT_SEEN:-<none>}', wanted 8 (octal dropped the floor)"
fi

# 37. a valid floor is actually in use.
gate_with_floor '9' 1
if [ "$WAIT_SEEN" = 9 ]; then
  ok 'a valid FRP_COMPAT_READY_MIN (9) floors the gate to 9'
else
  bad "valid readiness floor: the gate handed the ownership wait '${WAIT_SEEN:-<none>}', wanted 9"
fi

# 38. the gate itself refuses a non-decimal floor rather than reaching `(( ))`.
gate_rc=0
gate_out=$(FRP_COMPAT_READY_MIN=abc wait_for_port_safe 127.0.0.1 1 1 2>&1) || gate_rc=$?
case "$gate_out" in
  *"FRP_COMPAT_READY_MIN must be a non-negative integer"*) gate_msg=1 ;;
  *) gate_msg=0 ;;
esac
if [ "$gate_rc" = 1 ] && [ "$gate_msg" = 1 ]; then
  ok 'the gate refuses a non-decimal floor itself and fails closed'
else
  bad "gate-level floor refusal (rc=$gate_rc, message $( [ "$gate_msg" = 1 ] && echo present || echo missing ))"
fi

# 39. review round 3 audit: the XTCP shard's two halves reach `(( ))` too, where
#     a zero TOTAL is a division by zero and a padded one is an octal error.
#     Both are refused at load, before the phase can report "0 test(s) completed"
#     as a success. (`0/08` normalises to `0/8` instead of erroring; the strip is
#     the same one check 36 pins for the readiness floor.)
shard_rc=0
shard_out=$(run_harness_args --shard 0/0) || shard_rc=$?
case "$shard_out" in
  *"XTCP_SHARD needs 0 <= INDEX < TOTAL"*) shard_msg=1 ;;
  *) shard_msg=0 ;;
esac
if [ "$shard_rc" = 2 ] && [ "$shard_msg" = 1 ]; then
  ok 'a --shard whose TOTAL is 0 (a division by zero in the phase) is refused at load'
else
  bad "zero-TOTAL --shard (rc=$shard_rc, message $( [ "$shard_msg" = 1 ] && echo present || echo missing ))"
fi

# 40. a malformed shard is refused too, rather than reaching `(( ))`.
bad_shard_rc=0
bad_shard_out=$(run_harness_args --shard 1/x) || bad_shard_rc=$?
case "$bad_shard_out" in
  *"XTCP_SHARD must be INDEX/TOTAL"*) bad_shard_msg=1 ;;
  *) bad_shard_msg=0 ;;
esac
if [ "$bad_shard_rc" = 2 ] && [ "$bad_shard_msg" = 1 ]; then
  ok 'a non-decimal --shard (1/x) is refused at load too'
else
  bad "malformed --shard (rc=$bad_shard_rc, message $( [ "$bad_shard_msg" = 1 ] && echo present || echo missing ))"
fi
