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
# A synthetic server is a symlink named `frps` to `sleep`:
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
#   5  cleanup_pids waits on the tracked pids only: an untracked live child does
#      not hang the teardown before the guard can run.
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

[ -f "$LIB" ] || { printf 'FAIL  guard library not found: %s\n' "$LIB"; exit 1; }

checks=0
fails=0
ok()  { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf '  FAIL  %s\n' "$1"; }
hdr() { printf '\n%s\n' "$1"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/compat-guard.XXXXXX")"
LIVE=""   # every synthetic pid we start, for the exit trap

cleanup_all() {
  for p in $LIVE; do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup_all EXIT

sleep_bin=$(command -v sleep) || { printf 'FAIL  cannot find sleep\n'; exit 1; }
BASH_BIN=${BASH:-/bin/bash}
command -v pgrep >/dev/null 2>&1 || { printf 'FAIL  this fixture harness needs pgrep on PATH\n'; exit 1; }

# spawn_fake <dir-under-which-the-symlink-lives> -> echoes the pid on stdout
# The symlink is `<dir>/frps`; running it puts `<dir>/frps` in the command line,
# which is what makes the process match (or not match) `$TEST_DIR/`.
spawn_fake() {
  mkdir -p "$1"
  ln -sfn "$sleep_bin" "$1/frps"
  "$1/frps" 300 >/dev/null 2>&1 &
  printf '%s' "$!"
}

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
if kill -0 "$straypid" 2>/dev/null; then
  bad "stray $straypid survived the guard"
else
  ok "stray $straypid was reaped"
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
sleep 6 &                 # untracked: must not be waited on by cleanup_pids
untracked=$!
sleep 30 &                # tracked: reaped by cleanup_pids
tracked=$!
LIVE="$LIVE $untracked"
PIDS="$tracked"
started=$SECONDS
cleanup_pids
elapsed=$((SECONDS - started))
if [ "$elapsed" -lt 3 ]; then
  ok "cleanup_pids returned in ${elapsed}s with an untracked live child"
else
  bad "cleanup_pids took ${elapsed}s — it waited on an untracked child (bare \`wait\`)"
fi
if kill -0 "$tracked" 2>/dev/null; then
  bad "tracked pid $tracked survived cleanup_pids"
else
  ok 'tracked pid was reaped'
fi
if [ -z "$PIDS" ]; then ok 'PIDS reset after cleanup_pids'; else bad "PIDS not reset: $PIDS"; fi
kill -9 "$untracked" 2>/dev/null || true

# --- scenario 6: the scratch dir is documented as overridable ---------------
# The guard scopes itself to `$TEST_DIR/`, so two concurrent runs sharing the
# default would count and reap each other's servers; the fix is that the path is
# overridable (`scripts/compat-test.sh` line ~31). `--help` exits before the
# harness sources the guard, so this is a cheap, deterministic check.
hdr 'scenario 6: FRP_COMPAT_TEST_DIR is documented in --help'
out=$("$BASH_BIN" "$ROOT/scripts/compat-test.sh" --help 2>&1); rc=$?
if [ "$rc" -eq 0 ]; then ok 'compat-test.sh --help exits 0'; else bad "compat-test.sh --help rc $rc"; fi
case "$out" in
  *FRP_COMPAT_TEST_DIR*) ok '--help documents FRP_COMPAT_TEST_DIR' ;;
  *) bad '--help does not document FRP_COMPAT_TEST_DIR' ;;
esac

# ---------------------------------------------------------------- summary
hdr 'summary'
if [ "$fails" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
else
  printf 'RESULT: %d fixture check(s), %d failure(s) above\n' "$checks" "$fails"
fi
exit "$fails"
