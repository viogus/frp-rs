#!/usr/bin/env bash
# compat-port-ownership.sh — fixture checks for scripts/lib/compat-port-ownership.sh.
#
# Why this exists: the compat harness's two port failures both exit 0 on a green
# run, so nothing in the suite itself can show them.
#
#   * `random_port()` (`scripts/compat-test.sh`) drew a fresh random port per
#     call and remembered nothing, so one scenario could be handed the same port
#     twice — its echo listener and its frps, say (the TODO.md same-port-twice
#     item).
#   * every readiness gate accepted any socket that answered, so a scenario's own
#     echo listener, a leftover from an earlier scenario, or an unrelated process
#     satisfied a gate meant for the process that was just launched; and
#     `wait_for_port_safe` ended in `sleep "$timeout"; return 0`, a pass with no
#     listener at all.
#
# This suite drives the ledger and the ownership checks against real listeners
# (python3 sockets), a stripped `PATH` (no lsof/ss), and a fake `ss`, then reads
# the two callers for the wiring no runtime check can see (a helper that stops
# using the gate stays green at runtime).
#
# Scenarios
#   1  ledger: a one-port range is handed out once, remembered, and refused on
#      the second draw with the range in the message; `TEST_DIR=""` and `"/"`
#      are refused, and a pick without a usable ledger fails closed.
#   2  ownership: a registered auxiliary listener is ready while no
#      non-auxiliary process has been launched since it started.
#   3  collision (echo vs frps): once a process is launched after that listener,
#      the gate refuses the socket immediately — naming the listener's pid — and
#      the readiness wait fails without waiting out its timeout, instead of
#      sleeping 15 s and reporting the echo's socket ready.
#   4  collision (echo vs proxy): the same refusal after a second launch.
#   5  foreign listener: a socket this run did not start is never ready, and the
#      diagnostic says so.
#   6  nobody listening: rc 1, and the readiness wait's diagnostic says no owned
#      LISTEN socket appeared.
#   7  cannot tell: with neither lsof nor ss on `PATH`, the census reports rc 2
#      and every gate refuses to report the port ready — the vacuous pass is gone.
#   8  fake ss: the `ss -tlnp` `pid=` parse names the owner, that pid is accepted
#      when this run started it, and an unknown port is "nobody listening".
#   9  protocol-matrix: `wait_for_listen` sourced from `scripts/protocol-matrix.sh`
#      refuses a foreign socket (rc 1, naming the pid), accepts the row's own
#      pid, and fails closed with no expected pid.
#   10 wiring: `scripts/compat-test.sh` picks through the ledger, routes both
#      readiness gates through the ownership wait, registers all four auxiliary
#      starters with their launch generation, carries the `--test` fail-closed
#      gate, and has no `LAST_TRACKED_PID` left; `scripts/protocol-matrix.sh`
#      sources the lib, passes the row's pid at both gates, and only runs `main`
#      when executed.
#   11 selector: `--test <run_test function name>` (what `--list` prints) exits
#      non-zero, names the selector, and prints no ` RESULTS:` line — while
#      `--list` keeps printing the function names. The harness runs against
#      four stub binaries (the `FRP_COMPAT_*` seam in `scripts/compat-test.sh`)
#      and a scratch test dir, so this needs no build.
#   12 selector --debug: a traced run of a real display name reaches its
#      scenario, reports that scenario's own failure in the summary (the
#      `--debug` subshell used to discard it and print `0 passed, 0 failed`),
#      and does not claim the name matched nothing.
#   13 selector --skipped phase: a real display name whose phase was skipped in
#      this configuration is told apart from a typo.
#
# Self-contained: no network, no repo binaries, no Go frp, and no scenario
# reaches a real server. Every stubbed selector run pins `GO_FRP_VERSION` to
# `0.0.0-fixture.<pid>`, so the default Go directory the harness derives cannot
# exist; the suite asserts that directory is absent (the probe is not vacuous)
# and that the harness never printed its missing-binary error — so a real
# `/tmp/frp_0.71.0_*` left on the host by an earlier compat run cannot stand in
# for a stub and mask a broken seam. The stub-driven runs stop at the harness's
# own pre-gate executable check or at the stub's first missing listener.
# Temporary listeners and trees are removed on exit.
#
# Usage: bash scripts/tests/compat-port-ownership.sh
set -uo pipefail

# Resolve this script through symlinks before deriving the repo root, so
# invoking it through a link still finds `scripts/lib/`.
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
readonly SELF_REAL="$self"
ROOT=$(cd -P -- "$(dirname -- "$self")/../.." && pwd)
LIB="$ROOT/scripts/lib/compat-port-ownership.sh"
COMPAT="$ROOT/scripts/compat-test.sh"
MATRIX="$ROOT/scripts/protocol-matrix.sh"

checks=0
fails=0
# Pinned total: `exit "$fails"` alone is happy with `RESULT: 0 fixture check(s)
# hold`, so a suite that silently stops checking must not exit green. The floor
# and the ordered `SHAPE` below are enforced from the exit trap on every path,
# including an early `exit 0`.
MIN_CHECKS=59
# The ordered assertion anchors, one per `ok`/`bad` call in scenario order:
# a scenario that stops running, a deleted check, a reordered check, or a dummy
# `ok` anywhere all move `LABELS` away from this list.
SHAPE=(
  "ledger: a one-port range is handed out"
  "ledger: the handed-out port is remembered"
  "ledger: the range is exhausted after one draw"
  "ledger: the exhaustion diagnostic names the range and the draws"
  "ledger: an empty TEST_DIR is refused"
  "ledger: the TEST_DIR refusal names the variable"
  "ledger: a slash TEST_DIR is refused"
  "ledger: a pick fails closed without a usable TEST_DIR"
  "ledger: reset forgets the allocated port"
  "ownership: a python listener is listening"
  "ownership: a registered aux listener is ready"
  "ownership: the readiness wait accepts it"
  "collision (echo vs frps): a superseded aux listener is not ready"
  "collision (echo vs frps): the diagnostic names the listener pid"
  "collision (echo vs frps): the gate fails without waiting out its timeout"
  "collision (echo vs proxy): a twice-superseded aux listener is not ready"
  "collision (echo vs proxy): the readiness wait fails closed"
  "foreign listener: an untracked socket is not ready"
  "foreign listener: the diagnostic says this run did not start it"
  "foreign listener: the readiness wait fails closed"
  "nobody listening: cpo_ready_owned reports rc 1"
  "nobody listening: the readiness wait fails closed"
  "nobody listening: the diagnostic says no owned LISTEN socket appeared"
  "cannot tell: cpo_listen_owner reports rc 2 without a census tool"
  "cannot tell: cpo_ready_owned reports rc 2"
  "cannot tell: the readiness wait refuses to report ready"
  "cannot tell: the diagnostic names the missing census tools"
  "fake ss: pid= is parsed as the port owner"
  "fake ss: the parsed pid is accepted when this run started it"
  "fake ss: an unknown port is reported as nobody listening"
  "protocol-matrix: a python listener is listening"
  "matrix: a foreign socket does not green wait_for_listen"
  "matrix: the diagnostic names the foreign pid and the expected one"
  "matrix: the row's own pid greens wait_for_listen"
  "matrix: a call with no expected pid fails closed"
  "matrix: nobody listening times out as rc 1"
  "compat-test.sh: random_port delegates to the ledger"
  "compat-test.sh: sources the port-ownership lib"
  "compat-test.sh: both readiness gates route through the ownership wait"
  "compat-test.sh: all four aux starters register their pid and port"
  "compat-test.sh: the aux registration carries the launch generation"
  "compat-test.sh: no LAST_TRACKED_PID resurrection"
  "compat-test.sh: the selector gate names the unmatched selector"
  "compat-test.sh: should_run_test records a match"
  "protocol-matrix.sh: sources the port-ownership lib"
  "protocol-matrix.sh: both row gates pass the frps pid"
  "protocol-matrix.sh: main runs only when executed"
  "selector: the stubbed default Go dir is absent"
  "selector: a function-name --test exits non-zero"
  "selector: the message names the selector"
  "selector: no RESULTS summary is printed"
  "selector: --list still prints function names"
  "selector --debug: the traced run reaches the scenario"
  "selector --debug: no false unmatched-selector report"
  "selector --debug: the scenario failure reaches the summary"
  "selector --debug: the run exits non-zero for the failed scenario"
  "selector: a skipped-phase name exits non-zero"
  "selector: the skipped-phase message names the phase, not a typo"
  "selector: no stub run needed a real binary"
)

WORK="$(mktemp -d "${TMPDIR:-/tmp}/compat-port-ownership.XXXXXX")" || {
  printf 'FAIL  cannot create a scratch dir\n'; exit 1; }
LIVE=()
LABELS=()

# The lib's contract: these are the run's state. `TEST_DIR` is the ledger's home.
TEST_DIR="$WORK/ledger"
PIDS=""
AUX_LAUNCH_GEN=0

hdr() { printf '\n%s\n' "$1"; }
ok()  { checks=$((checks + 1)); LABELS+=("$1"); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); LABELS+=("$1"); printf '  FAIL  %s\n' "$1"; }

enforce_shape() {
  local i n=${#SHAPE[@]} want got
  if [ "${#LABELS[@]}" -ne "$n" ]; then
    printf 'FAIL  check shape changed: %d assertion(s) ran, expected %d\n' \
      "${#LABELS[@]}" "$n" >&2
    return 1
  fi
  for (( i = 0; i < n; i++ )); do
    want=${SHAPE[i]}
    got=${LABELS[i]}
    case "$got" in
      *"$want"*) ;;
      *) printf 'FAIL  check %d is not the expected assertion: got %q, wanted one matching %q\n' \
           "$((i + 1))" "$got" "$want" >&2
         return 1 ;;
    esac
  done
  return 0
}

below_floor() {
  # Ordered digit-string comparison: `[ … -lt … ]` cannot parse an all-digit
  # floor above the signed 64-bit range, and `if` reads that status 2 as false.
  # Both operands are validated digits before this is called, so the comparison
  # is deliberately lexical, not arithmetic.
  # shellcheck disable=SC2071
  [ "${#checks}" -lt "${#MIN_CHECKS}" ] ||
    { [ "${#checks}" -eq "${#MIN_CHECKS}" ] && [[ "$checks" < "$MIN_CHECKS" ]]; }
}

cleanup_all() {
  local rc=$? i
  for i in "${LIVE[@]:-}"; do
    [ -n "$i" ] && kill "$i" 2>/dev/null
  done
  [ -z "$WORK" ] || rm -rf "$WORK"
  # `bad()` counts a failure but leaves the exit status alone, so a red run used
  # to reach the `rc -eq 0` branch below, satisfy the floor and the shape, and
  # print `RESULT: … hold` with rc 0 — the failure was reported but not exited.
  # A run that counted a failure fails, whatever its status was.
  if [ "$rc" -eq 0 ] && [ "$fails" -gt 0 ]; then
    rc=1
  fi
  if [ "$rc" -eq 0 ]; then
    case ${MIN_CHECKS:-} in
      ''|0)
        printf 'FAIL  the check floor is disabled (MIN_CHECKS=%s); the suite cannot vouch for itself\n' \
          "${MIN_CHECKS:-<unset>}" >&2
        rc=1
        ;;
      *[!0-9]*)
        printf 'FAIL  the check floor is not a number (MIN_CHECKS=%s); the suite cannot vouch for itself\n' \
          "$MIN_CHECKS" >&2
        rc=1
        ;;
      *)
        # A zero-padded floor denotes 0 but skips the `0)` arm, so strip the
        # zeros first.
        local min_raw=$MIN_CHECKS
        while [ "${MIN_CHECKS#0}" != "$MIN_CHECKS" ]; do
          MIN_CHECKS=${MIN_CHECKS#0}
        done
        if [ -z "$MIN_CHECKS" ]; then
          printf 'FAIL  the check floor is disabled (MIN_CHECKS=%s); the suite cannot vouch for itself\n' \
            "$min_raw" >&2
          rc=1
        elif below_floor; then
          printf 'FAIL  suite exited 0 after only %s check(s); expected at least %s — scenarios did not run\n' \
            "$checks" "$MIN_CHECKS" >&2
          rc=1
        elif ! ( enforce_shape ); then
          rc=1
        fi
        ;;
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

[ -f "$LIB" ] || { printf 'FAIL  port-ownership library not found: %s\n' "$LIB"; exit 1; }
# shellcheck source=scripts/lib/compat-port-ownership.sh
source "$LIB"

# --- helpers -----------------------------------------------------------------

# check_rc <want> <label> -- <cmd...>   (stdout/stderr dropped)
check_rc() {
  local want="$1" label="$2" rc=0
  shift 2
  [ "${1:-}" = "--" ] && shift
  "$@" >/dev/null 2>&1 || rc=$?
  if [ "$rc" = "$want" ]; then
    ok "$label"
  else
    bad "$label (rc=$rc, wanted $want)"
  fi
}

# check_msg <label> <pattern> -- <cmd...>   (rc ignored; pattern is literally in
# the command's combined output — used for diagnostics the caller never reads)
check_msg() {
  local label="$1" pat="$2" out=""
  shift 2
  [ "${1:-}" = "--" ] && shift
  out="$("$@" 2>&1)"
  case "$out" in
    *"$pat"*) ok "$label" ;;
    *) bad "$label (output did not contain '$pat')" ;;
  esac
}

# check_rc_msg <want> <label> <pattern> -- <cmd...>
check_rc_msg() {
  local want="$1" label="$2" pat="$3" rc=0 out=""
  shift 3
  [ "${1:-}" = "--" ] && shift
  out="$("$@" 2>&1)" || rc=$?
  if [ "$rc" != "$want" ]; then
    bad "$label (rc=$rc, wanted $want)"
  else
    case "$out" in
      *"$pat"*) ok "$label" ;;
      *) bad "$label (output did not contain '$pat')" ;;
    esac
  fi
}

# A real LISTEN socket, started with python3 and reaped on exit. `LIS_PID` is the
# caller's; the connect probe below is python3 so the wait itself needs no
# lsof/ss (the ownership checks are the things under test).
spawn_listener() {
  local port="$1" i
  python3 -c '
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(8)
time.sleep(120)
' "$port" >/dev/null 2>&1 &
  LIS_PID=$!
  LIVE+=("$LIS_PID")
  # Disown so the teardown's `kill` does not make bash print a job-control
  # "Terminated" notice after the summary.
  disown "$LIS_PID" 2>/dev/null || true
  for (( i = 0; i < 50; i++ )); do
    python3 -c '
import socket, sys
s = socket.socket()
s.settimeout(2)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
' "$port" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

pick_fixture_port() {
  local min="$1" max="$2" port=""
  port=$( (CPO_PORT_MIN="$min"; CPO_PORT_MAX="$max"; cpo_pick_port) 2>/dev/null ) || return 1
  [ -n "$port" ] || return 1
  printf '%s\n' "$port"
}

for c in "$LIB" "$COMPAT" "$MATRIX"; do
  [ -f "$c" ] || { printf 'FAIL  missing file under test: %s\n' "$c"; exit 1; }
done
command -v python3 >/dev/null 2>&1 || { printf 'FAIL  python3 is required; not found\n'; exit 1; }

# --- scenario 1: the ledger --------------------------------------------------

hdr 'ledger'
cpo_ledger_reset >/dev/null 2>&1 || true

led_out=$( (CPO_PORT_MIN=19800; CPO_PORT_MAX=19800; cpo_pick_port) 2>/dev/null )
led_rc=$?
if [ "$led_rc" = 0 ] && [ "$led_out" = 19800 ]; then
  ok 'ledger: a one-port range is handed out'
else
  bad "ledger: a one-port range is handed out (rc=$led_rc, got '$led_out')"
fi

check_rc 0 'ledger: the handed-out port is remembered' -- cpo_port_allocated 19800
# The second draw runs in a subshell, not `bash -c`: the ledger file is keyed on
# the run's pid (`$$`), which a subshell shares and an exec'd shell does not.
exh_out=$( (CPO_PORT_MIN=19800; CPO_PORT_MAX=19800; cpo_pick_port) 2>&1 )
exh_rc=$?
if [ "$exh_rc" = 1 ]; then
  ok 'ledger: the range is exhausted after one draw'
else
  bad "ledger: the range is exhausted after one draw (rc=$exh_rc)"
fi
case "$exh_out" in
  *'no free port in 19800-19800 after 1 draws'*)
    ok 'ledger: the exhaustion diagnostic names the range and the draws' ;;
  *) bad 'ledger: the exhaustion diagnostic names the range and the draws' ;;
esac

saved_testdir="$TEST_DIR"
TEST_DIR=""
check_rc_msg 1 'ledger: an empty TEST_DIR is refused' 'TEST_DIR is' -- cpo_ledger_ok
check_rc_msg 1 'ledger: the TEST_DIR refusal names the variable' 'refusing a port ledger there' -- cpo_ledger_ok
TEST_DIR="/"
check_rc 1 'ledger: a slash TEST_DIR is refused' -- cpo_ledger_ok
TEST_DIR=""
check_rc 2 'ledger: a pick fails closed without a usable TEST_DIR' -- cpo_pick_port
TEST_DIR="$saved_testdir"
cpo_ledger_reset >/dev/null 2>&1 || true
check_rc 1 'ledger: reset forgets the allocated port' -- cpo_port_allocated 19800

# --- scenario 2: a registered auxiliary listener is ready --------------------

hdr 'ownership'
cpo_ledger_reset >/dev/null 2>&1 || true
PIDS=""
AUX_LAUNCH_GEN=0
echo_port=$(pick_fixture_port 21000 21999) || true
[ -n "$echo_port" ] || { printf 'FAIL  no fixture port available for the listener\n'; exit 1; }
check_rc 0 'ownership: a python listener is listening' -- spawn_listener "$echo_port"
PIDS=" $LIS_PID "
cpo_register_listener echo "$echo_port" "$LIS_PID" "$AUX_LAUNCH_GEN" >/dev/null 2>&1 || true
check_rc 0 'ownership: a registered aux listener is ready' -- cpo_ready_owned "$echo_port"
check_rc 0 'ownership: the readiness wait accepts it' -- cpo_wait_port_ready "$echo_port" 2

# --- scenario 3/4: the forced collisions -------------------------------------

hdr 'collision'
AUX_LAUNCH_GEN=1
check_rc 3 'collision (echo vs frps): a superseded aux listener is not ready' -- cpo_ready_owned "$echo_port"
check_msg 'collision (echo vs frps): the diagnostic names the listener pid' "(pid $LIS_PID)" \
  -- cpo_ready_owned "$echo_port"
t0=$SECONDS
cpo_wait_port_ready "$echo_port" 30 >/dev/null 2>&1
col_rc=$?
col_el=$((SECONDS - t0))
if [ "$col_rc" = 1 ] && [ "$col_el" -lt 5 ]; then
  ok 'collision (echo vs frps): the gate fails without waiting out its timeout'
else
  bad "collision (echo vs frps): the gate fails without waiting out its timeout (rc=$col_rc after ${col_el}s)"
fi

AUX_LAUNCH_GEN=2
check_rc 3 'collision (echo vs proxy): a twice-superseded aux listener is not ready' -- cpo_ready_owned "$echo_port"
check_rc 1 'collision (echo vs proxy): the readiness wait fails closed' -- cpo_wait_port_ready "$echo_port" 2

# --- scenario 5: a foreign listener ------------------------------------------

hdr 'foreign'
PIDS=""
check_rc 3 'foreign listener: an untracked socket is not ready' -- cpo_ready_owned "$echo_port"
check_msg 'foreign listener: the diagnostic says this run did not start it' 'which this run did not start' \
  -- cpo_ready_owned "$echo_port"
check_rc 1 'foreign listener: the readiness wait fails closed' -- cpo_wait_port_ready "$echo_port" 2

# --- scenario 6: nobody listening --------------------------------------------

hdr 'nobody'
free_port=$(pick_fixture_port 22000 22999) || true
[ -n "$free_port" ] || { printf 'FAIL  no free fixture port available\n'; exit 1; }
check_rc 1 'nobody listening: cpo_ready_owned reports rc 1' -- cpo_ready_owned "$free_port"
check_rc 1 'nobody listening: the readiness wait fails closed' -- cpo_wait_port_ready "$free_port" 1
check_msg 'nobody listening: the diagnostic says no owned LISTEN socket appeared' \
  'never had a LISTEN socket owned by this run' -- cpo_wait_port_ready "$free_port" 1

# --- scenario 7: cannot tell (no lsof, no ss) --------------------------------

hdr 'cannot tell'
np="$WORK/nopath"
mkdir -p "$np"
ln -sf "$(command -v sleep)" "$np/sleep" 2>/dev/null || true
nopath_listen_owner() { ( PATH="$np"; cpo_listen_owner "$1" ); }
nopath_ready_owned()  { ( PATH="$np"; cpo_ready_owned "$1" ); }
nopath_wait_ready()   { ( PATH="$np"; cpo_wait_port_ready "$1" "$2" ); }
PIDS=" $LIS_PID "
AUX_LAUNCH_GEN=0
check_rc 2 'cannot tell: cpo_listen_owner reports rc 2 without a census tool' -- nopath_listen_owner "$echo_port"
check_rc 2 'cannot tell: cpo_ready_owned reports rc 2' -- nopath_ready_owned "$echo_port"
check_rc 1 'cannot tell: the readiness wait refuses to report ready' -- nopath_wait_ready "$echo_port" 1
check_msg 'cannot tell: the diagnostic names the missing census tools' \
  'neither lsof nor ss is installed' -- nopath_wait_ready "$echo_port" 1

# --- scenario 8: the `ss -tlnp` parse ----------------------------------------

hdr 'fake ss'
fakess="$WORK/fakess"
mkdir -p "$fakess"
ln -sf "$(command -v sleep)" "$fakess/sleep" 2>/dev/null || true
# The lib's `ss` branch pipes the census through grep and sed, so the fake PATH
# needs those too — otherwise the parse fails for the wrong reason.
ln -sf "$(command -v grep)" "$fakess/grep" 2>/dev/null || true
ln -sf "$(command -v sed)" "$fakess/sed" 2>/dev/null || true
cat > "$fakess/ss" <<FAKESS
#!/bin/bash
# minimal \`ss -tlnp "sport = :PORT"\` stand-in for the fixture.
for a in "\$@"; do
  case "\$a" in *:*) port=\${a##*:} ;; esac
done
if [ "\${port:-}" = "$echo_port" ]; then
  printf '%s\n' 'State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process'
  printf '%s\n' 'LISTEN 0      128        127.0.0.1:$echo_port    0.0.0.0:*    users:(("python3",pid=$LIS_PID,fd=3))'
fi
FAKESS
chmod +x "$fakess/ss"
fakess_listen_owner() { ( PATH="$fakess"; cpo_listen_owner "$1" ); }
fakess_ready_owned()  { ( PATH="$fakess"; cpo_ready_owned "$1" ); }
fs_out=$(fakess_listen_owner "$echo_port" 2>/dev/null)
fs_rc=$?
if [ "$fs_rc" = 0 ] && [ "$fs_out" = "$LIS_PID" ]; then
  ok 'fake ss: pid= is parsed as the port owner'
else
  bad "fake ss: pid= is parsed as the port owner (rc=$fs_rc, got '$fs_out')"
fi
check_rc 0 'fake ss: the parsed pid is accepted when this run started it' -- fakess_ready_owned "$echo_port"
check_rc 1 'fake ss: an unknown port is reported as nobody listening' -- fakess_listen_owner "$free_port"

# --- scenario 9: protocol-matrix's wait_for_listen, sourced ------------------

hdr 'protocol-matrix'
PIDS=""
AUX_LAUNCH_GEN=0
mport=$(pick_fixture_port 23000 23999) || true
dead_port=$(pick_fixture_port 24000 24999) || true
[ -n "$mport" ] && [ -n "$dead_port" ] || { printf 'FAIL  no fixture port available for the matrix checks\n'; exit 1; }
check_rc 0 'protocol-matrix: a python listener is listening' -- spawn_listener "$mport"
m_pid=$LIS_PID
check_rc 1 'matrix: a foreign socket does not green wait_for_listen' \
  -- bash -c "source '$MATRIX'; wait_for_listen '$mport' 2 999999"
m_diag=$(bash -c "source '$MATRIX'; wait_for_listen '$mport' 2 999999" 2>&1)
case "$m_diag" in
  *"pid(s) $m_pid"*"not this row's pid 999999"*)
    ok 'matrix: the diagnostic names the foreign pid and the expected one' ;;
  *) bad 'matrix: the diagnostic names the foreign pid and the expected one' ;;
esac
check_rc 0 "matrix: the row's own pid greens wait_for_listen" \
  -- bash -c "source '$MATRIX'; wait_for_listen '$mport' 2 '$m_pid'"
check_rc 1 'matrix: a call with no expected pid fails closed' \
  -- bash -c "source '$MATRIX'; wait_for_listen '$mport' 2"
check_rc 1 'matrix: nobody listening times out as rc 1' \
  -- bash -c "source '$MATRIX'; wait_for_listen '$dead_port' 1 '$m_pid'"

# --- scenario 10: the wiring in the two callers ------------------------------

hdr 'wiring'
if grep -A25 '^random_port()' "$COMPAT" | grep -q 'cpo_pick_port'; then
  ok 'compat-test.sh: random_port delegates to the ledger'
else
  bad 'compat-test.sh: random_port delegates to the ledger'
fi
if grep -q 'lib/compat-port-ownership.sh' "$COMPAT"; then
  ok 'compat-test.sh: sources the port-ownership lib'
else
  bad 'compat-test.sh: sources the port-ownership lib'
fi
gate_calls=$(grep -c '^ *cpo_wait_port_ready ' "$COMPAT" 2>/dev/null || true)
if [ "$gate_calls" = 2 ]; then
  ok 'compat-test.sh: both readiness gates route through the ownership wait'
else
  bad "compat-test.sh: both readiness gates route through the ownership wait ($gate_calls calls)"
fi
aux_calls=$(grep -c '^ *track_aux_pid [a-z]' "$COMPAT" 2>/dev/null || true)
if [ "$aux_calls" = 4 ]; then
  ok 'compat-test.sh: all four aux starters register their pid and port'
else
  bad "compat-test.sh: all four aux starters register their pid and port ($aux_calls calls)"
fi
if grep -q 'cpo_register_listener "$role" "$port" "$pid" "$AUX_LAUNCH_GEN"' "$COMPAT"; then
  ok 'compat-test.sh: the aux registration carries the launch generation'
else
  bad 'compat-test.sh: the aux registration carries the launch generation'
fi
if grep -q 'LAST_TRACKED_PID' "$COMPAT"; then
  bad 'compat-test.sh: no LAST_TRACKED_PID resurrection'
else
  ok 'compat-test.sh: no LAST_TRACKED_PID resurrection'
fi
if grep -q "matched no scenario" "$COMPAT"; then
  ok 'compat-test.sh: the selector gate names the unmatched selector'
else
  bad 'compat-test.sh: the selector gate names the unmatched selector'
fi
if grep -q 'SELECTED_MATCHED=true' "$COMPAT"; then
  ok 'compat-test.sh: should_run_test records a match'
else
  bad 'compat-test.sh: should_run_test records a match'
fi
if grep -q 'lib/compat-port-ownership.sh' "$MATRIX"; then
  ok 'protocol-matrix.sh: sources the port-ownership lib'
else
  bad 'protocol-matrix.sh: sources the port-ownership lib'
fi
if grep -Fq 'wait_for_listen "$srv_port" 20 "$frps_pid"' "$MATRIX" &&
  grep -Fq 'wait_for_listen "$proxy_port" 45 "$frps_pid"' "$MATRIX"; then
  ok 'protocol-matrix.sh: both row gates pass the frps pid'
else
  bad 'protocol-matrix.sh: both row gates pass the frps pid'
fi
if grep -Fq 'if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then' "$MATRIX" && ! grep -qx 'main' "$MATRIX"; then
  ok 'protocol-matrix.sh: main runs only when executed'
else
  bad 'protocol-matrix.sh: main runs only when executed'
fi

# --- scenarios 11-13: the harness's own --test handling ----------------------

# The `health` job has no `target/`, so driving the real harness needs the
# executable-path seam (`scripts/compat-test.sh`, the `FRP_COMPAT_*` overrides)
# and four stubs that satisfy the harness's pre-gate executable check. The seam
# must also be honoured where the harness recomputes `GO_FRP_DIR` from
# `GO_FRP_VERSION`, so every run below pins `GO_FRP_VERSION` to a version whose
# default Go directory cannot exist. Without that, a host that happens to have
# `/tmp/frp_0.71.0_<os>_<arch>` — which this repo's own local compat runs leave
# behind — would satisfy the pre-gate check with the real binaries and hide a
# seam that a clean runner cannot use. The version carries this run's pid, so
# the derived directory is provably absent, and the absence is asserted rather
# than assumed.
STUB_VERSION="0.0.0-fixture.$$"
_stub_os=$(uname -s | tr '[:upper:]' '[:lower:]')
_stub_arch=$(uname -m)
case "$_stub_arch" in
  x86_64) _stub_arch=amd64 ;;
  aarch64|arm64) _stub_arch=arm64 ;;
esac
STUB_GO_DIR="/tmp/frp_${STUB_VERSION}_${_stub_os}_${_stub_arch}"

STUB_DIR="$WORK/stubs"
mkdir -p "$STUB_DIR"
make_stub() {
  printf '#!/usr/bin/env bash\nprintf "%%s 0.71.0\\n" "%s"\n' "$1" > "$STUB_DIR/$1"
  chmod +x "$STUB_DIR/$1"
}
make_stub gofrps
make_stub gofrpc
make_stub rustfrps
make_stub rustfrpc

stub_out=""
stub_rc=0
# Set if any stubbed run prints the harness's missing-binary error: the seam did
# not take effect and the run fell back to the (nonexistent) default paths.
stub_missing_binary=0
run_stubbed() {
  stub_out=$(GO_FRP_VERSION="$STUB_VERSION" \
    FRP_COMPAT_GO_FRPS="$STUB_DIR/gofrps" \
    FRP_COMPAT_GO_FRPC="$STUB_DIR/gofrpc" \
    FRP_COMPAT_RUST_FRPS="$STUB_DIR/rustfrps" \
    FRP_COMPAT_RUST_FRPC="$STUB_DIR/rustfrpc" \
    FRP_COMPAT_TEST_DIR="$WORK/harness-tmp" \
    bash "$COMPAT" "$@" 2>&1)
  stub_rc=$?
  case "$stub_out" in
    *'Binary not found or not executable'*) stub_missing_binary=1 ;;
  esac
}

# The harness colors its ` RESULTS:` line even when redirected, so the summary
# is matched with the escapes stripped.
strip_ansi() {
  sed $'s/\033\\[[0-9;]*[A-Za-z]//g' <<<"$1"
}

hdr 'selector'
# The run below has to be hermetic on any host. This is the default Go directory
# the harness derives from `STUB_VERSION`; it cannot exist, and checking that is
# what keeps the stub run from passing on the host's real Go binaries instead.
if [ ! -e "$STUB_GO_DIR" ]; then
  ok 'selector: the stubbed default Go dir is absent'
else
  bad "selector: the stubbed default Go dir is absent (found $STUB_GO_DIR)"
fi
run_stubbed --ci --test test_g2r_tcp_plain
if [ "$stub_rc" -eq 2 ]; then
  ok 'selector: a function-name --test exits non-zero'
else
  bad "selector: a function-name --test exits non-zero (rc=$stub_rc)"
fi
case "$stub_out" in
  *"--test 'test_g2r_tcp_plain' matched no scenario"*)
    ok 'selector: the message names the selector' ;;
  *) bad 'selector: the message names the selector' ;;
esac
case "$stub_out" in
  *' RESULTS:'*)
    bad 'selector: no RESULTS summary is printed' ;;
  *) ok 'selector: no RESULTS summary is printed' ;;
esac
if bash "$COMPAT" --list 2>/dev/null | grep -qx 'test_g2r_tcp_plain'; then
  ok 'selector: --list still prints function names'
else
  bad 'selector: --list still prints function names'
fi

hdr 'selector --debug'
# `run_test` used to run the scenario in a subshell under `--debug`, which threw
# away `PASS`/`FAIL`, `PIDS` and the `--test` match: a traced run of a scenario
# that had just failed still printed ` RESULTS: 0 passed, 0 failed`, and its
# servers survived to trip the stray guard. The stub never listens, so the
# scenario fails at its first server gate and the summary has to carry that.
run_stubbed --ci --debug --test go-to-rust-tcp-plain
stub_plain=$(strip_ansi "$stub_out")
case "$stub_plain" in
  *'=== go-to-rust-tcp-plain ==='*)
    ok 'selector --debug: the traced run reaches the scenario' ;;
  *) bad 'selector --debug: the traced run reaches the scenario' ;;
esac
case "$stub_plain" in
  *'matched no scenario'*)
    bad 'selector --debug: no false unmatched-selector report' ;;
  *) ok 'selector --debug: no false unmatched-selector report' ;;
esac
case "$stub_plain" in
  *' RESULTS: 0 passed, 1 failed'*)
    ok 'selector --debug: the scenario failure reaches the summary' ;;
  *) bad 'selector --debug: the scenario failure reaches the summary' ;;
esac
if [ "$stub_rc" -eq 1 ]; then
  ok 'selector --debug: the run exits non-zero for the failed scenario'
else
  bad "selector --debug: the run exits non-zero for the failed scenario (rc=$stub_rc)"
fi

hdr 'selector --skipped phase'
# `xtcp-g2g-basic` is a real display name (a `run_xtcp_test` first argument) that
# this configuration skips. Telling that caller its name matched nothing sent it
# looking for a typo that was not there.
run_stubbed --ci --test xtcp-g2g-basic
if [ "$stub_rc" -eq 2 ]; then
  ok 'selector: a skipped-phase name exits non-zero'
else
  bad "selector: a skipped-phase name exits non-zero (rc=$stub_rc)"
fi
case "$stub_out" in
  *'names a scenario this run did not execute'*)
    ok 'selector: the skipped-phase message names the phase, not a typo' ;;
  *) bad 'selector: the skipped-phase message names the phase, not a typo' ;;
esac

# Aggregated over all three stubbed runs above. A seam that is ignored where the
# harness recomputes `GO_FRP_DIR` falls back to the default paths, which do not
# exist here, so the harness dies at its executable check instead of reaching the
# selector gate — exactly what a clean CI runner saw.
if [ "$stub_missing_binary" -eq 0 ]; then
  ok 'selector: no stub run needed a real binary'
else
  bad 'selector: no stub run needed a real binary'
fi
