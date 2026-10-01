#!/usr/bin/env bash
# compat-stray-guard.sh — fixture checks for scripts/lib/compat-stray-guard.sh.
#
# Why this exists: the stray guard is the only thing that catches a leaked
# compat server, and every one of its failure modes still exits 0 — a census
# tool that is missing, a `TEST_DIR` that matches everything, or a name-only
# match that reaps a peer worktree's server. A green compat run cannot show any
# of that, so the guard is driven here against synthetic `frps` processes whose
# name is real and whose command line is the only thing that distinguishes them.
#
# A synthetic server is a symlink named `frps` to `sleep` (scenario 5's two
# helpers use the same trick under the name `helper`, where the process name is
# not the point):
# `pgrep -x frps` sees the name (the kernel names a process after the path it was
# exec'd through, symlink included), `ps -o command=` shows that path, and the
# process is long-lived and port-free. No compat server, no ports, no repo
# binaries.
#
# Scenarios
#   1  clean run: assert_no_strays returns 0, and neither an in-`$TEST_DIR`
#      server already running at load time (the baseline) nor a same-named peer
#      outside `$TEST_DIR` is touched.
#   2  stray present: the in-`$TEST_DIR` server is named in the report, reaped,
#      and the guard returns 1 — while the same-named peer survives. This is the
#      tooth a name-only match reds (it would reap the peer and fail the run).
#   3  census tool missing: `pgrep` absent from `PATH` is a hard failure, not an
#      empty census.
#   4  degenerate `TEST_DIR`: empty and `/` are refused outright (with
#      `TEST_DIR=""` the ownership pattern `*"$TEST_DIR/"*` becomes `*/*` and
#      would match an unrelated process).
#   5  cleanup_pids waits on the tracked pids only: an untracked live child is
#      still running when the teardown returns, rather than being waited on.
#   6  the scratch dir is documented as overridable, so a concurrent compat run
#      does not share this run's census.
#   7  `wait_exec`'s "has the child exec-ed yet" anchor still works when this
#      file is invoked through a symlink whose name differs from the real one
#      (the anchor must not be derived from the resolved script name).
#   8  a `ps` that exits 0 with empty output is "cannot tell", not "the image
#      changed" — it must not be read as "the helper has exec-ed".
#   9  a `ps` that fails in the exit trap does not turn a live synthetic of ours
#      into a stranger: an unidentifiable pid we started is still killed.
#   10 `scripts/compat-test.sh` carries no pattern kill and its XTCP pre-test
#      sweep is the pid-exact `reap_scoped_strays` (TODO.md:8063).
#   11 that sweep, driven against three real synthetic servers: the
#      in-`$TEST_DIR` leak started after the baseline is reaped, while the
#      baseline server and the same-named out-of-tree peer are left alone. This
#      is what keeps the helper from rotting behind scenario 10's source read.
#
# Self-contained: no network, no compat run, no dependence on this repo's
# binaries. Temporary trees and synthetic processes are removed on exit.
#
# Usage: bash scripts/tests/compat-stray-guard.sh
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
ROOT=$(cd -P -- "$(dirname -- "$self")/../.." && pwd)
LIB="$ROOT/scripts/lib/compat-stray-guard.sh"

# The census probe. A seam, not a constant, because the two "cannot tell"
# failure directions it has — a probe that *fails*, and a probe that succeeds
# with empty output — are only observable by handing `wait_exec` and the exit
# trap a probe that does exactly that (scenarios 8 and 9).
PROBE_PS_DEFAULT=${PROBE_PS:-ps}
PROBE_PS=$PROBE_PS_DEFAULT

checks=0
fails=0
# Pinned total. This suite is the only thing that pins the guard, so a suite
# that silently stops checking must not exit green: `exit "$fails"` alone is
# happy with `RESULT: 0 fixture check(s) hold`. `cleanup_all` enforces the floor
# on every exit path, and it is installed before this file's first failure
# point, so an early `exit 0` — a neutered scenario body, say — cannot skip it.
# A total is not a *shape* though: deleting N assertions and adding N dummy
# `ok` lines keeps the total and still exits 0 (measured against the count as
# the only guard — that mutant is in the batch-E record), which is residue (d)
# of TODO.md:8146. `SHAPE` below pins the count, the order and the *label* of
# every assertion, so a scenario that stops running, a check that is deleted,
# reordered, or a dummy added anywhere, all red. It compares labels, not bodies:
# a check whose body is gutted behind an unchanged `ok` label is not a shape
# failure, and the mutant that replaces scenario 10's `hits=$(grep …)` with
# `hits=''` exits 0 on `SHAPE` alone.
#
# `enforce_substance` below narrows that label-only class for scenario 10: it
# checksums the scenario-10 region byte-for-byte, from the `compat_src=` input
# derivation through both assertion blocks, so editing the grep, gutting either
# verdict in place, forging the text either one reads, or dropping a marker all
# red. It does not authenticate *behaviour*: relocating the pinned region
# verbatim behind `if false; then … fi` and leaving a bare `ok` with the same
# label in the live path keeps the region byte-identical, and that mutant still
# exits 0 (measured). That is a declared residue, not a defence — closing it
# needs a construct that cannot be relocated, and the batch-E round-3 report
# records it for TODO.md. Only scenario 10 gets even this much; a body gutted
# anywhere else still needs a reviewer.
#
# A floor of 0 (or an unset floor) disables the guard from inside, which the
# sibling suite learned the hard way; that is a failure here too. So is a
# zero-padded floor: `00`/`000` are all digits but denote 0, so the floor is
# normalised before it is compared (R2-2), and the below-floor diagnostic prints
# the decimal value rather than `printf`'s octal reading of it (R2-3). Digits
# alone were *not* sufficient either (R3-1): a floor above `9223372036854775807`
# is unparseable as an integer, so the below-floor test is an ordered comparison
# of digit strings and such a floor is a below-floor failure, not a status-2 skip.
MIN_CHECKS=31
# The ordered assertion anchors, one per `ok`/`bad` call in scenario order.
# Dynamic parts (pids, elapsed seconds) are matched as substrings, so each entry
# is the stable prefix/skeleton of the assertion it pins.
SHAPE=(
  'pgrep -x frps sees synthetic server pid'
  'clean run: assert_no_strays returned 0'
  'baseline server survived'
  'out-of-tree peer survived'
  'stray present: assert_no_strays returned 1'
  'report names the stray pid'
  'was reaped'
  'out-of-tree peer still survives'
  'missing pgrep: load failed with rc'
  'missing pgrep: the error names pgrep'
  'empty TEST_DIR: refused'
  'empty TEST_DIR: the error names TEST_DIR'
  'TEST_DIR=/: refused'
  'TEST_DIR=/: the error explains the degradation'
  "has exec'd its own image"
  'untracked child was still running when cleanup_pids returned'
  'cleanup_pids returned in'
  'tracked pid was reaped'
  'PIDS reset after cleanup_pids'
  'compat-test.sh --help exits 0'
  '--help documents FRP_COMPAT_TEST_DIR'
  'symlink invocation: wait_exec returned 1 for the pre-exec fork'
  'wait_exec reports rc 2 when ps prints nothing'
  'wait_exec reports rc 2 when ps prints nothing for the child'
  'ps failure: unidentifiable synthetic'
  'ps exit-0-empty: unidentifiable synthetic'
  'compat-test.sh: no pkill/killall/pgrep -f in its code'
  'compat-test.sh: run_xtcp_test sweeps with cleanup_pids and reap_scoped_strays'
  'pre-test sweep: reaped the in-TEST_DIR stray'
  'pre-test sweep: left the baseline server alone'
  'pre-test sweep: left the out-of-tree peer alone'
)
LABELS=()
# Every synthetic pid we start. The trap reaps each one that is still ours,
# including the scenario-5 helpers, so no scenario has to be the only net under
# a process it spawned.
LIVE=""
WORK=""

# reap_own_synthetic — kill each synthetic this suite started that is still
# ours. Ownership is still the scratch dir's basename in the argv (it survives
# `/var` -> `/private/var` normalisation); what changed is the failure
# direction. A `ps` probe that cannot run leaves the pid *unidentifiable*, and
# an unidentifiable live child we started is ours to kill — reading it as "not
# ours" is how every live synthetic outlived a `ps` failure (residue (a) of
# TODO.md:8146). A pid the guard already reaped can be recycled before this trap
# runs, and killing a stranger is the hazard this suite pins; the probe is what
# tells those apart, so only a probe we can trust is allowed to *forgive*.
reap_own_synthetic() {
  local p cmd
  for p in $LIVE; do
    if ! cmd=$("$PROBE_PS" -o command= -p "$p" 2>/dev/null); then
      kill -9 "$p" 2>/dev/null || true
      continue
    fi
    case "$cmd" in
      '') kill -9 "$p" 2>/dev/null || true ;;
      *"/${WORK##*/}/"*) kill -9 "$p" 2>/dev/null || true ;;
    esac
  done
}

# run_with_probe_ps <fake-ps> <command...> — run a command against a fake `ps`
# and restore the real probe on every path, so the exit trap never inherits a
# stub and the scenarios below cannot leak a seam into each other.
run_with_probe_ps() {
  local fake=$1 rc=0
  shift
  PROBE_PS="$fake"
  "$@" || rc=$?
  PROBE_PS=$PROBE_PS_DEFAULT
  return "$rc"
}

# enforce_shape — the ordered-assertion half of the floor.
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

# enforce_substance — the substance half of the floor, for the scenario-10
# region that pins TODO.md:8063's fix. `enforce_shape` compares labels, and a
# label survives a replaced body (`hits=''` behind the same `ok`), so that
# region's exact source text is checksummed: the input derivation
# (`compat_src=`, the comment strip) *and* both assertion blocks. Pinning only
# the two verdict blocks left the line that produces the text they read
# unpinned, so a forged input — a literal string containing `cleanup_pids` and
# `reap_scoped_strays`, with `scripts/compat-test.sh` never opened — kept both
# checksums and stayed green (reviewer 2, R2-1/LIE; measured). The region is
# delimited by the `substance pin:` markers in scenario 10; an edit inside it
# reds until the constant below is updated, and the failure text prints the
# value to paste. It adds no `ok`/`bad` call of its own, so it can never move the
# fixture count — or the ci.yml literal that pins it — by itself.
SCEN10_REGION_SHA='d8430f18448caeff61ff025c59cd62ed34a55214fa0f785e3fc44102e5006211'
scen10_region_sha() {
  local tool
  if command -v sha256sum >/dev/null 2>&1; then
    tool='sha256sum'
  elif command -v shasum >/dev/null 2>&1; then
    tool='shasum -a 256'
  else
    printf 'FAIL  no sha256 tool on PATH (need sha256sum or shasum); cannot check scenario 10 substance\n' >&2
    return 1
  fi
  # shellcheck disable=SC2086  # $tool is the word-split "shasum -a 256"
  sed -n '/^# --- substance pin: scenario-10 /,/^# --- end substance pin: scenario-10 ---/p' "$self" |
    $tool | awk '{print $1}'
}
enforce_substance() {
  local got
  got=$(scen10_region_sha) || return 1
  if [ "$got" != "$SCEN10_REGION_SHA" ]; then
    printf 'FAIL  scenario 10 region changed: sha256 %s, pinned %s\n' \
      "${got:-<none>}" "$SCEN10_REGION_SHA" >&2
    printf '      deliberate edit? set SCEN10_REGION_SHA in %s to the value above\n' \
      "${self:-this script}" >&2
    return 1
  fi
  return 0
}

cleanup_all() {
  local rc=$? min_raw
  reap_own_synthetic
  [ -z "$WORK" ] || rm -rf "$WORK"
  if [ "$rc" -eq 0 ]; then
    # Fail closed: `[ NaN -lt 1 ]` is status 2, and `if`/`elif` read status 2 as
    # false, so an unparseable floor used to skip every branch below and exit 0.
    # `enforce_shape` happened to mask that here (a deleted check moves `LABELS`),
    # but a comparison that cannot parse its operands must never be the guard of
    # record — validate the digits first, then compare the digit strings in
    # order, exactly as the sibling suite does, so an all-digit floor too large
    # for `-lt` is a below-floor failure rather than a status-2 skip (R3-1).
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
        # The digits-only arm above still lets a zero-padded floor through:
        # `00`/`000` denote 0 but never reach the `0)` arm, so the floor was
        # silently off (R2-2). Strip the leading zeros — a plain string strip,
        # not `$(( … ))`, whose base detection is the thing being avoided — and
        # treat the result as the floor; `min_raw` keeps the spelling for the
        # diagnostic. Only zeros leave an empty string, which is the disabled
        # case in the value it denotes.
        min_raw=$MIN_CHECKS
        while [ "${MIN_CHECKS#0}" != "$MIN_CHECKS" ]; do
          MIN_CHECKS=${MIN_CHECKS#0}
        done
        if [ -z "$MIN_CHECKS" ]; then
          printf 'FAIL  the check floor is disabled (MIN_CHECKS=%s); the suite cannot vouch for itself\n' \
            "$min_raw" >&2
          rc=1
        else
          case $checks in
            ''|*[!0-9]*)
              printf 'FAIL  the check counter is not a number (%s); the suite cannot vouch for itself\n' \
                "$checks" >&2
              rc=1
              ;;
            *)
              # Same ordered digit-string comparison as the sibling suite (see
              # its R3-1 note): `[ … -lt … ]` returns status 2 on an all-digit
              # floor above the signed 64-bit range, which `if` reads as false
              # and which here would hand the floor's verdict to `enforce_shape`.
              if [ "${#checks}" -lt "${#MIN_CHECKS}" ] ||
                { [ "${#checks}" -eq "${#MIN_CHECKS}" ] && [ "$checks" \< "$MIN_CHECKS" ]; }; then
                printf 'FAIL  suite exited 0 after only %s check(s); expected at least %s — scenarios did not run\n' \
                  "$checks" "$MIN_CHECKS" >&2
                rc=1
              elif ! enforce_shape; then
                rc=1
              elif ! enforce_substance; then
                rc=1
              fi
              ;;
          esac
        fi
        ;;
    esac
  fi
  exit "$rc"
}
trap cleanup_all EXIT

[ -f "$LIB" ] || { printf 'FAIL  guard library not found: %s\n' "$LIB"; exit 1; }

# `LABELS` records every assertion in the order it ran (both verdicts), which is
# what `enforce_shape` compares against `SHAPE` on a green exit: a total alone
# cannot tell a scenario that stopped running from four dummy `ok` lines.
ok()  { checks=$((checks + 1)); LABELS+=("$1"); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); LABELS+=("$1"); printf '  FAIL  %s\n' "$1"; }
hdr() { printf '\n%s\n' "$1"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/compat-guard.XXXXXX")"

sleep_bin=$(command -v sleep) || { printf 'FAIL  cannot find sleep\n'; exit 1; }
BASH_BIN=${BASH:-/bin/bash}
command -v pgrep >/dev/null 2>&1 || { printf 'FAIL  this fixture harness needs pgrep on PATH\n'; exit 1; }

# spawn_fake <dir-under-which-the-symlink-lives> [name] -> echoes the pid
# The symlink is `<dir>/<name>` (default `frps`); running it puts that path in
# the command line, which is what makes the process match (or not match)
# `$TEST_DIR/` and what the exit trap's ownership predicate matches on.
spawn_fake() {
  local dir=$1 name=${2:-frps}
  mkdir -p "$dir"
  ln -sfn "$sleep_bin" "$dir/$name"
  "$dir/$name" 300 >/dev/null 2>&1 &
  printf '%s' "$!"
}

# wait_exec <pid> — synchronise on the child's own image before signalling it: a
# child signalled before it has exec'd may not have taken the signal yet, so
# scenario 5 waits here before `cleanup_pids` sends SIGTERM. The pre-fix shape
# (signalling first, with the untracked helper bounded at 6 s) reddened ~1 run in
# 5 at load 28-40 with `cleanup_pids took 10s`; that red's mechanism could not be
# reproduced in the round-2 re-check (300/300 immediate SIGTERMs to a freshly
# spawned `sleep 30` landed within 0.25 s, and 25/25 old-shape runs at load 42-47
# were fast), so this is a cheap defensive synchronisation, not a reproduced
# root-cause fix. Returns 0 once the image changed, 1 if it never did within 2 s,
# and 2 when the `ps` probe itself fails or prints nothing: "could not
# synchronise" must not read as "synced".
#
# The anchor is this shell's own command line, read from the same probe: a
# forked, not-yet-exec'd child has an identical argv, and after `exec` it can
# never match. It used to be `basename` of the *resolved* script path, which the
# child's argv does not carry when the suite is invoked through a symlink with a
# different name — the match failed before the exec and `wait_exec` returned 0
# (residue (b) of TODO.md:8146). Nothing here depends on the file's name, so
# there is no alias to get wrong.
wait_exec() {
  local pid=$1 i=0 cmd me
  if ! me=$("$PROBE_PS" -o command= -p "$$" 2>/dev/null); then
    printf 'wait_exec: ps -p %s failed; cannot tell whether the helper has exec-ed yet\n' "$$" >&2
    return 2
  fi
  if [ -z "$me" ]; then
    printf 'wait_exec: ps -p %s printed nothing; cannot tell whether the helper has exec-ed yet\n' "$$" >&2
    return 2
  fi
  while (( i < 100 )); do
    if ! cmd=$("$PROBE_PS" -o command= -p "$pid" 2>/dev/null); then
      printf 'wait_exec: ps -p %s failed; cannot tell whether the helper has exec-ed yet\n' "$pid" >&2
      return 2
    fi
    if [ -z "$cmd" ]; then
      printf 'wait_exec: ps -p %s printed nothing; cannot tell whether the helper has exec-ed yet\n' "$pid" >&2
      return 2
    fi
    case "$cmd" in "$me") ;; *) return 0 ;; esac
    sleep 0.02
    i=$((i + 1))
  done
  return 1
}

# wait_gone <pid> — SIGKILL delivery and reaping are asynchronous, so `kill -0`
# succeeding immediately after a `kill -9` is not "the process survived the
# guard". Polls for up to 2 s and returns 1 only if the pid is still there.
wait_gone() {
  local pid=$1 i=0
  while (( i < 100 )); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.02
    i=$((i + 1))
  done
  return 1
}

# --- probe mode: measure `wait_exec` from a deliberately aliased invocation ---
# Scenario 7 runs this file through a symlink whose name differs from the real
# one, so the child's argv carries the alias; before the fix the anchor was the
# *resolved* script name, which that argv does not contain, and the "has it
# exec-ed yet" test matched before the exec. This block is the only way to
# observe that from inside the file (there is no other window between fork and
# exec), and it exits before the first assertion so it can never move a fixture
# count. `wait_exec "$$"` asks about the child *running this block*: it has not
# exec-ed, so the only correct answer is 1.
if [ -n "${FRP_STRAY_GUARD_PROBE:-}" ]; then
  wait_exec "$$"; _probe_rc=$?
  printf 'probe wait_exec self rc=%d\n' "$_probe_rc"
  trap - EXIT
  [ -z "$WORK" ] || rm -rf "$WORK"
  exit 0
fi

# --- fixture self-check: the synthetic server must be visible at all ---------
# Without this the whole file could pass because `pgrep -x frps` never matched
# anything — the same vacuity the guard itself refuses.
selfdir="$WORK/selfcheck"
selfpid=$(spawn_fake "$selfdir")
LIVE="$LIVE $selfpid"
seen=false
for _ in $(seq 1 50); do
  if pgrep -x frps 2>/dev/null | grep -qx "$selfpid"; then seen=true; break; fi
  sleep 0.1
done
hdr 'fixture setup: a symlink named `frps` is visible to `pgrep -x frps`'
if $seen; then
  ok "pgrep -x frps sees synthetic server pid $selfpid"
else
  bad "pgrep -x frps does not see synthetic server pid $selfpid — the fixture would be vacuous"
fi
kill -9 "$selfpid" 2>/dev/null || true

# --- scenario 1: clean run, baseline and out-of-tree peer both survive -------
hdr 'scenario 1: clean run returns 0; baseline and same-named peer survive'
td1="$WORK/run1"
mkdir -p "$td1"
# Already running when the guard loads -> baseline, not ours to reap.
prepid=$(spawn_fake "$td1/bin-old")
LIVE="$LIVE $prepid"
export TEST_DIR="$td1"
# shellcheck source=/dev/null
source "$LIB"
# A sibling's server, started *after* this run's baseline: same process name,
# path outside `$TEST_DIR`. It must not be counted, reaped or failed on — a
# name-only match is exactly what would do all three.
peerpid=$(spawn_fake "$WORK/peer1")
LIVE="$LIVE $peerpid"
sleep 0.3
if assert_no_strays; then
  ok 'clean run: assert_no_strays returned 0'
else
  bad "clean run: assert_no_strays returned $? (expected 0)"
fi
kill -0 "$prepid" 2>/dev/null && ok 'baseline server survived' || bad 'baseline server was reaped'
kill -0 "$peerpid" 2>/dev/null && ok 'out-of-tree peer survived' || bad 'out-of-tree peer was reaped'

# --- scenario 2: an in-`$TEST_DIR` stray is named, reaped and fails the run --
hdr 'scenario 2: in-TEST_DIR stray is reaped and returns 1; peer still survives'
td2="$WORK/run2"
mkdir -p "$td2"
export TEST_DIR="$td2"
# Re-source: the baseline is recomputed per run, and nothing under `$td2` is
# running yet, so the server started below cannot hide in the baseline.
# shellcheck source=/dev/null
source "$LIB"
straypid=$(spawn_fake "$td2/scenario")
LIVE="$LIVE $straypid"   # the guard should reap it; the exit trap is the net
sleep 0.3
out=$(assert_no_strays 2>&1); rc=$?
if [ "$rc" -eq 1 ]; then
  ok 'stray present: assert_no_strays returned 1'
else
  bad "stray present: expected rc 1, got $rc"
fi
case "$out" in
  *"$straypid"*) ok "report names the stray pid $straypid" ;;
  *) bad "report does not name the stray pid: $(printf '%s' "$out" | tr '\n' ' ')" ;;
esac
if wait_gone "$straypid"; then
  ok "stray $straypid was reaped"
else
  bad "stray $straypid survived the guard"
fi
if kill -0 "$peerpid" 2>/dev/null; then
  ok 'out-of-tree peer still survives (name-only match would have killed it)'
else
  bad 'out-of-tree peer was killed — the predicate matched on name alone'
fi

# --- scenario 3: a missing pgrep is a hard failure, not an empty census ------
hdr 'scenario 3: missing pgrep refuses to run'
out=$(env PATH=/nonexistent TEST_DIR="$WORK/run3" "$BASH_BIN" -c 'source "$1"' _ "$LIB" 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then
  ok "missing pgrep: load failed with rc $rc"
else
  bad 'missing pgrep: guard loaded successfully (vacuous census)'
fi
case "$out" in
  *'requires `pgrep`'*) ok 'missing pgrep: the error names pgrep' ;;
  *) bad "missing pgrep: unexpected output: $(printf '%s' "$out" | tr '\n' ' ')" ;;
esac

# --- scenario 4: degenerate TEST_DIR is refused ------------------------------
hdr 'scenario 4: empty or `/` TEST_DIR is refused'
out=$(env TEST_DIR= "$BASH_BIN" -c 'source "$1"' _ "$LIB" 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then ok 'empty TEST_DIR: refused'; else bad 'empty TEST_DIR: accepted'; fi
case "$out" in
  *'requires TEST_DIR to be set'*) ok 'empty TEST_DIR: the error names TEST_DIR' ;;
  *) bad "empty TEST_DIR: unexpected output: $(printf '%s' "$out" | tr '\n' ' ')" ;;
esac
out=$(env TEST_DIR=/ "$BASH_BIN" -c 'source "$1"' _ "$LIB" 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then ok 'TEST_DIR=/: refused'; else bad 'TEST_DIR=/: accepted'; fi
case "$out" in
  *'refusing to guard'*) ok 'TEST_DIR=/: the error explains the degradation' ;;
  *) bad "TEST_DIR=/: unexpected output: $(printf '%s' "$out" | tr '\n' ' ')" ;;
esac

# --- scenario 5: cleanup_pids waits on tracked pids only ---------------------
hdr 'scenario 5: cleanup_pids does not wait on an untracked child'
export TEST_DIR="$WORK/run5"
# shellcheck source=/dev/null
source "$LIB"
# Both helpers are synthetic servers under `$WORK` (symlinks to `sleep`, exactly
# like `spawn_fake`'s), so the exit trap's directory-scoped predicate reaps them
# and "every synthetic pid we start" is true rather than aspirational: deleting
# the explicit leg below cannot leave the untracked one behind. `cleanup_pids`
# only ever sees the tracked one.
untracked=$(spawn_fake "$WORK/run5-untracked" helper)
tracked=$(spawn_fake "$WORK/run5-tracked" helper)
LIVE="$LIVE $untracked $tracked"
PIDS="$tracked"
# Synchronise before signalling: a child signalled before it has exec'd may not
# have taken the signal yet, so `kill` here could miss and let the grace loop run
# its full 10 s deadline on a healthy run (see `wait_exec` for what was and was
# not reproducible about the pre-fix red). rc 2 means the `ps` probe itself
# failed, which must be reported rather than read as "synced".
wait_exec "$tracked"; wrc=$?
case "$wrc" in
  0) ok "tracked helper $tracked has exec'd its own image" ;;
  1) bad "tracked helper $tracked is still the forked shell after the 2s sync deadline" ;;
  *) bad "could not synchronise on tracked helper $tracked: \`ps\` failed (wait_exec rc $wrc)" ;;
esac
started=$SECONDS
cleanup_pids
elapsed=$((SECONDS - started))
# The property is "cleanup_pids returned while the untracked child was still
# running", not a wall-clock bound: the grace loop above may legitimately spend
# up to 10 s on a tracked server that ignores SIGTERM, so a tight `elapsed < N`
# reds on healthy runs. A bare `wait` cannot return while the untracked child
# lives, so this liveness check is the tooth; the 20 s bound below is only a hang
# guard (slack over the 10 s grace, well under the helper's 300 s).
if kill -0 "$untracked" 2>/dev/null; then
  ok 'untracked child was still running when cleanup_pids returned'
else
  bad 'untracked child was gone when cleanup_pids returned — cleanup_pids waited on it'
fi
if [ "$elapsed" -lt 20 ]; then
  ok "cleanup_pids returned in ${elapsed}s with an untracked live child"
else
  bad "cleanup_pids took ${elapsed}s — it waited on an untracked child (bare \`wait\`)"
fi
if wait_gone "$tracked"; then
  ok 'tracked pid was reaped'
else
  bad "tracked pid $tracked survived cleanup_pids"
fi
if [ -z "$PIDS" ]; then ok 'PIDS reset after cleanup_pids'; else bad "PIDS not reset: $PIDS"; fi
kill -9 "$untracked" 2>/dev/null || true
wait "$untracked" 2>/dev/null || true

# --- scenario 6: the scratch dir is documented as overridable ---------------
# The guard scopes itself to `$TEST_DIR/`, so two concurrent runs sharing the
# default would count and reap each other's servers; the fix is that the path is
# overridable (`scripts/compat-test.sh` sets
# `TEST_DIR="${FRP_COMPAT_TEST_DIR:-/tmp/frp-compat-test}"`). `--help` exits
# before the harness sources the guard, so this is a cheap, deterministic check.
hdr 'scenario 6: FRP_COMPAT_TEST_DIR is documented in --help'
out=$("$BASH_BIN" "$ROOT/scripts/compat-test.sh" --help 2>&1); rc=$?
if [ "$rc" -eq 0 ]; then ok 'compat-test.sh --help exits 0'; else bad "compat-test.sh --help rc $rc"; fi
case "$out" in
  *FRP_COMPAT_TEST_DIR*) ok '--help documents FRP_COMPAT_TEST_DIR' ;;
  *) bad '--help does not document FRP_COMPAT_TEST_DIR' ;;
esac

# --- scenario 7: `wait_exec`'s anchor survives an aliased invocation ---------
# Residue (b) of TODO.md:8146. The probe child is this same file under a
# different name: `wait_exec "$$"` must still see its own pre-exec fork and
# return 1. Any anchor derived from the script's own name fails here, which is
# exactly the latent bug CI (which calls the direct path) could not see.
hdr 'scenario 7: wait_exec still sees its own pre-exec fork through a symlink'
alias_link="$WORK/alias-probe.sh"
# `self` may be a relative path (this script never `cd`s), and a relative
# symlink target would be resolved against `$WORK`, not the caller's cwd.
alias_target=$self
case "$alias_target" in /*) ;; *) alias_target=$PWD/$alias_target ;; esac
ln -sfn "$alias_target" "$alias_link"
out=$(env FRP_STRAY_GUARD_PROBE=1 "$BASH_BIN" "$alias_link" 2>&1); rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = 'probe wait_exec self rc=1' ]; then
  ok 'symlink invocation: wait_exec returned 1 for the pre-exec fork'
else
  bad "symlink invocation: expected 'probe wait_exec self rc=1' with rc 0, got rc $rc: $(printf '%s' "$out" | tr '\n' ' ')"
fi

# --- scenario 8: empty `ps` output is "cannot tell", not "the image changed" -
# Residue (c) of TODO.md:8146. A probe that exits 0 with no output used to fall
# through to the `*) return 0` arm — an empty string does not contain the anchor
# — so "the tool told us nothing" was read as "the helper has exec-ed".
hdr 'scenario 8: wait_exec reads empty ps output as "cannot tell"'
fakeps_empty="$WORK/fakeps-empty"
printf '#!/bin/sh\nexit 0\n' > "$fakeps_empty"
chmod +x "$fakeps_empty"
wout=$(run_with_probe_ps "$fakeps_empty" wait_exec "$$" 2>&1); wrc=$?
msg=false
case "$wout" in *'printed nothing'*) msg=true ;; esac
if [ "$wrc" -eq 2 ] && $msg; then
  ok 'wait_exec reports rc 2 when ps prints nothing'
else
  bad "wait_exec returned $wrc (message pinned: $msg) when ps printed nothing (expected rc 2 — 'cannot tell' must not read as 'synced')"
fi

# --- scenario 8b: the same read, but for the *child* probe --------------------
# Reviewer 1's residue. Scenario 8 hands `wait_exec` a `ps` that prints nothing
# for every pid, so it returns at the `$$` guard and the loop's own empty-`cmd`
# guard is never the one that fires; deleting that guard stayed green against
# scenario 8 alone (measured). Here the fake `ps` answers every pid *except* the
# child with a non-empty argv, so the `$$` guard passes and the loop guard is
# the only one that can produce the rc 2.
hdr 'scenario 8b: wait_exec reads empty ps output for the child as "cannot tell"'
child_victim=$(spawn_fake "$WORK/run8b-victim")
LIVE="$LIVE $child_victim"
# The one pid that gets no output is baked in at generation time, so the stub
# never has to reason about `$$` inside a command substitution. Any other pid —
# including the `me` probe — gets a non-empty line the child's cannot match.
fakeps_child_empty="$WORK/fakeps-child-empty"
printf '#!/bin/sh\nlast=\nfor a in "$@"; do last=$a; done\nif [ "$last" != "%s" ]; then printf "fixture-parent-argv\\n"; fi\nexit 0\n' \
  "$child_victim" > "$fakeps_child_empty"
chmod +x "$fakeps_child_empty"
cout=$(run_with_probe_ps "$fakeps_child_empty" wait_exec "$child_victim" 2>&1); crc=$?
cmsg=false
case "$cout" in *"ps -p $child_victim printed nothing"*) cmsg=true ;; esac
if [ "$crc" -eq 2 ] && $cmsg; then
  ok 'wait_exec reports rc 2 when ps prints nothing for the child'
else
  bad "wait_exec returned $crc (child message pinned: $cmsg) when ps printed nothing for the child (expected rc 2 — the parent probe answered, so only the loop's empty-cmd guard can fire)"
fi
kill -9 "$child_victim" 2>/dev/null || true

# --- scenario 9: a failed ownership probe does not forgive a live synthetic --
# Residue (a) of TODO.md:8146. The victim is a real synthetic of this run, under
# `$WORK`, so the *real* predicate would match it; the point is that a probe
# which cannot run must not be read as "not ours" and let it outlive the suite.
hdr 'scenario 9: a failed ps probe does not turn a live synthetic into a stranger'
fakeps_fail="$WORK/fakeps-fail"
printf '#!/bin/sh\nexit 1\n' > "$fakeps_fail"
chmod +x "$fakeps_fail"
victim=$(spawn_fake "$WORK/run9-victim")
LIVE="$LIVE $victim"
run_with_probe_ps "$fakeps_fail" reap_own_synthetic
if wait_gone "$victim"; then
  ok "ps failure: unidentifiable synthetic $victim was killed"
else
  bad "ps failure: synthetic $victim survived — a probe that could not run was read as 'not ours'"
  kill -9 "$victim" 2>/dev/null || true
fi

# --- scenario 9b: an exit-0-empty probe still reaps a live synthetic ----------
# Reviewer 1's residue. Scenario 9's fake `ps` exits 1, so it exercises only the
# failed-probe arm at `reap_own_synthetic`'s first branch; the neighbouring
# `'') kill -9 "$p"` arm — the probe that runs and says nothing — was therefore
# unverified, and deleting that arm stayed green (measured). Scenario 8's
# `$fakeps_empty` (exit 0, no output) is exactly the probe that reaches it. The
# subshell scopes `LIVE` to the single victim so this sweep cannot touch another
# scenario's servers.
hdr 'scenario 9b: an exit-0-empty ps probe does not forgive a live synthetic'
victim9b=$(spawn_fake "$WORK/run9b-victim")
LIVE="$LIVE $victim9b"
( LIVE="$victim9b"; run_with_probe_ps "$fakeps_empty" reap_own_synthetic )
if wait_gone "$victim9b"; then
  ok "ps exit-0-empty: unidentifiable synthetic $victim9b was killed"
else
  bad "ps exit-0-empty: synthetic $victim9b survived — a probe that ran and said nothing was read as 'not ours'"
  kill -9 "$victim9b" 2>/dev/null || true
fi

# --- scenario 10: the XTCP pre-test cleanup is pid-exact (TODO.md:8063) ------
# `run_xtcp_test` used two `pkill -f "frpc -c"` / `pkill -f "frps -c"` calls,
# which select any process on the host whose command line carries that pattern —
# a developer's unrelated run, or a sibling worktree's compat run. The
# replacement is the reaper the closed compat-leak item added, driven by the
# pids this run recorded, and that is what the two assertions below pin. The
# pattern kill itself is not executed here (the repository forbids running one
# at all), so this is the source-shape half of the mutant that reds the fix.
hdr 'scenario 10: compat-test.sh kills by pid, not by argument pattern'
# --- substance pin: scenario-10 (checksummed by enforce_substance) ---
compat_src="$ROOT/scripts/compat-test.sh"
# Comments are stripped first, and both checks below read the stripped text: a
# comment naming a forbidden command (the replacement's own rationale names
# `pkill -f`, and `cleanup_pids` appears in comments above the call) is neither a
# kill nor a sweep. Reading the raw source let a mutant that replaced the
# `cleanup_pids` call with `:` stay green off the surrounding comment — measured
# on the mutant below, not hypothetical.
compat_code=$(sed 's/[[:space:]]*#.*$//' "$compat_src")
# Both reads go through a file, not `printf | …`: `awk` stops at the function's
# closing brace, and a builtin `printf` on the far end of that closed pipe
# reports `printf: write error: Broken pipe` on stderr (measured) — noise in the
# CI log for a check that passed.
printf '%s\n' "$compat_code" > "$WORK/compat-test.code"
hits=$(grep -nE '(^|[^[:alnum:]_])(pkill|killall)([[:space:]]|$)|(^|[^[:alnum:]_])pgrep[[:space:]]+-[^[:space:]]*f' "$WORK/compat-test.code" || true)
if [ -z "$hits" ]; then
  ok 'compat-test.sh: no pkill/killall/pgrep -f in its code'
else
  bad "compat-test.sh kills by pattern again: $(printf '%s' "$hits" | tr '\n' ' ')"
fi
xtcp_body=$(awk '/^run_xtcp_test\(\)/{f=1} f{print} f&&/^}/{exit}' "$WORK/compat-test.code")
# TODO.md:8063 replaced *two* pattern kills with a pid-exact pair, so the
# scenario has to see both halves inside `run_xtcp_test`: the tracked-pid reaper
# (`cleanup_pids`, TODO 7866's first replacement) and the guard's baseline-aware
# census sweep (`reap_scoped_strays`). Pinning only the latter let a mutant that
# deleted the `cleanup_pids` call stay green (measured, reviewer 1).
xtcp_calls=$(printf '%s\n' "$xtcp_body" | grep -cE '^[[:space:]]*cleanup_pids([[:space:]]|$)' || true)
xtcp_sweep=false
case "$xtcp_body" in *'reap_scoped_strays'*) xtcp_sweep=true ;; esac
if $xtcp_sweep && [ "$xtcp_calls" -ge 1 ]; then
  ok 'compat-test.sh: run_xtcp_test sweeps with cleanup_pids and reap_scoped_strays'
else
  bad "compat-test.sh: run_xtcp_test's pre-test cleanup is incomplete (reap_scoped_strays=$xtcp_sweep, cleanup_pids calls=$xtcp_calls) — TODO.md:8063 needs both, one per pkill -f it replaced"
fi
# --- end substance pin: scenario-10 ---

# --- scenario 11: the pre-test sweep itself, driven against real servers ------
# Scenario 10 only reads the source; the helper it names has to *run* somewhere
# or the sweep rots behind a green shape check (the lesson of scenario 10's own
# mutant, which matched a comment). This drives `reap_scoped_strays` against
# three synthetic `frps` servers: one started before the guard loaded (baseline),
# one outside `$TEST_DIR` (a sibling's, same process name), and one in-`$TEST_DIR`
# leak started after the baseline. Only the leak may be reaped.
hdr 'scenario 11: the pre-test sweep reaps an in-TEST_DIR leak and nothing else'
td11="$WORK/run11"
mkdir -p "$td11"
baseline11=$(spawn_fake "$td11/baseline-old")
LIVE="$LIVE $baseline11"
export TEST_DIR="$td11"
# shellcheck source=/dev/null
source "$LIB"
peer11=$(spawn_fake "$WORK/run11-peer")
LIVE="$LIVE $peer11"
leak11=$(spawn_fake "$td11/provider")
LIVE="$LIVE $leak11"
sleep 0.3
reap_scoped_strays
if wait_gone "$leak11"; then
  ok "pre-test sweep: reaped the in-TEST_DIR stray $leak11"
else
  bad "pre-test sweep: in-TEST_DIR stray $leak11 survived — the sweep found nothing to reap"
fi
if kill -0 "$baseline11" 2>/dev/null; then
  ok 'pre-test sweep: left the baseline server alone'
else
  bad 'pre-test sweep: the baseline server was reaped — the sweep ignored the baseline'
fi
if kill -0 "$peer11" 2>/dev/null; then
  ok 'pre-test sweep: left the out-of-tree peer alone'
else
  bad 'pre-test sweep: the out-of-tree peer was reaped — the sweep matched on name alone'
fi
kill -9 "$baseline11" "$peer11" 2>/dev/null || true

# ---------------------------------------------------------------- summary
hdr 'summary'
if [ "$fails" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
else
  printf 'RESULT: %d fixture check(s), %d failure(s) above\n' "$checks" "$fails"
fi
exit "$fails"
