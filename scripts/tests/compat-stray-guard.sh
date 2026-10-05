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
#      sweep is the pid-exact `reap_scoped_strays` (TODO.md:9759).
#   11 that sweep, driven against three real synthetic servers: the
#      in-`$TEST_DIR` leak started after the baseline is reaped, while the
#      baseline server and the same-named out-of-tree peer are left alone. This
#      is what keeps the helper from rotting behind scenario 10's source read.
#   12 a trailing-slash `TEST_DIR` — the documented `FRP_COMPAT_TEST_DIR`
#      override as shell completion spells it — still counts, names and reaps an
#      in-`$TEST_DIR` stray: the library normalises the spelling, so it cannot
#      silently empty the census.
#   13 an untrusted `ps` in the shipped census is a hard error, not an empty
#      census: a probe that fails, one that exits 0 with no output, and one that
#      fails only for the exit trap's report format all refuse instead of
#      forgiving a live in-`$TEST_DIR` stray.
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
# F1 (adversarial round 5): bind the resolved path, and have the enforcer compare
# what `region_sha` read against *that* binding instead of against `$self`
# itself. While `region_sha` reported `$self` and `enforce_substance` compared it
# with `$self`, the check was a tautology — the same mutable global on both
# sides — so one inserted `self=<unmodified copy>` line redirected every pin to
# a file the edit never touched (measured GREEN on both suites). `readonly self`
# alone is not enough either: on bash 3.2 (macOS) a reassignment of a readonly
# is reported but *ignored* — the old value survives and the script still exits
# 0 — so the guarantee has to live in the comparison. `SELF_REAL` is captured
# once here, before anything else can run, and is the value `region_pin_check`
# holds every checksum path against: a pre-call `self=<copy>` now reads the
# wrong file and reds on every bash.
readonly SELF_REAL="$self"
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
# of TODO.md:9892. `SHAPE` below pins the count, the order and the *label* of
# every assertion, so a scenario that stops running, a check that is deleted,
# reordered, or a dummy added anywhere, all red. It compares labels, not bodies:
# a check whose body is gutted behind an unchanged `ok` label is not a shape
# failure, and the mutant that replaces scenario 10's `hits=$(grep …)` with
# `hits=''` exits 0 on `SHAPE` alone.
#
# `enforce_substance` below narrows that label-only class for the scenarios the
# reviews demonstrated: scenario 2 (SG-M1), scenario 10 (R2-1/LIE) and the two
# round-6 regression tests, scenario 12 (F2) and scenario 13 (F3). Each named
# region is checksummed byte-for-byte — scenario 10 from the `compat_src=` input
# derivation through both assertion blocks, the other three whole — so editing
# the grep, gutting a verdict in place, forging the text a check reads, or
# dropping a marker all red. It does not authenticate *behaviour*: relocating a
# pinned region verbatim behind `if false; then … fi` and leaving a bare `ok`
# with the same label in the live path keeps the region byte-identical, and that
# mutant still exits 0 (measured). That is a declared residue (N4), not a
# defence — closing it needs a construct that cannot be relocated, and the
# batch-E report records it for TODO.md. The scenarios outside those regions
# (1, 3–9b, 11) are unpinned; a body gutted there still needs a reviewer.
#
# Round 12 closes the one-line routes the round-10 adversarial reopened: a
# `case` whitelist over the expectations, a `case` that skips every name but one,
# a `region_sha` that fabricates a digest, or replacing the real pin loop's call
# with an assigned count — each used to leave every in-file check green while the
# regions went unhashed. The count is now the hasher's own `name=digest` ledger
# (`region_hash_verdict`), so no call site can claim a count it did not earn; a
# content-mutation probe hashes a one-byte-different copy of a pinned region and
# requires the honest comparison to reject it. Round 13 records each completed
# probe in a ledger `enforce_substance` asserts, so gutting the probe reds
# in-suite instead of silently skipping it, and computes the copy's digest
# independently of `region_sha`. Round 14 extends that probe to all four pinned
# regions and makes the ledger `name=copy-digest`: the caller re-hashes the copies
# on disk and re-runs the comparison against each in both directions. What is
# proven is therefore that `region_sha` returns the *bytes'* digest for every
# pinned region — a digest keyed on the path (`real file → pin`, else empty) fails
# the agreement check, and a digest keyed on the region *name* (a plausible
# constant for scenario-10/scenario-12, the two the round-13 probe never walked)
# now fails it too. Probed on the mutants below, not claimed.
# The `health` CI step pins this file *and* the library it sources
# (`scripts/lib/compat-stray-guard.sh`, from the `source` calls in the scenarios
# rather than from the `LIB=` assignment) before running it, so an edit to either
# half of the guard is a two-file change a reviewer sees. That is the honest
# boundary: the guard catches careless single-region edits. It does not prevent
# pin removal — an edit here plus a refreshed `SCEN*_REGION_SHA` (L2), or a
# forged summary and evidence block (L1), is still green. Those stay declared
# residues, not defences. Files outside the pinned set: `scripts/compat-test.sh`
# (the wider compat harness, not run by this step) and the sources of the other
# fixture suites.
#
# Round 14 (F1) paths, part 2: the digest *read* is PATH-free by construction —
# `region_lines` uses `read`/`case`/`printf`, `${x%% *}` splits the hasher's
# output and `$HASH_TOOL` is absolute and vector-proven — so a shadowed `awk` or
# `sed` can no longer mint a region's bytes or its digest. Demonstrated, not
# asserted: on the pre-fix tree an `awk` shim answering only `{print $1}` kept a
# drifted scenario-10 green and this step exited 0; it reds now.
#
# What remains is the declared boundary. (R14-a) the *fixtures'* inspections of
# other files (`grep`, `sed`, `awk` in the scenario bodies — e.g. scenario-10's
# read of `scripts/compat-test.sh`, or the `xtcp_body` parse further down) still
# resolve through PATH, so a shim can answer a probe the way the scenario wants:
# with a `grep` that reports "no hits", a `pkill -f` regression in that unpinned
# file ships while this step still prints `pins verified 4/4` and exits 0 — a
# genuine false negative in a scenario, never in the pin. That boundary is
# reachable, and it is the accepted one: an unpinned in-repo file such as
# `scripts/compat-test.sh`, or the `scripts/repo-health.sh` step above, can put a
# shim earlier on `$PATH` (GitHub's `$GITHUB_PATH` persists it into later steps).
# (R14-b) `flip_hex`'s `tr` and the `mktemp` probe directory are PATH-resolved,
# but both are fail-closed only — a `tr` that returns its input makes the canary's
# injected "wrong" pin correct and reds, and a directory from `mktemp` cannot
# forge the ledger the caller re-derives from the copies. (R14-c) a shadowed
# `bash` (the interpreter) or a replaced absolute `/usr/bin/sha256sum` owns the
# process and is out of scope; checking the verifier's own toolchain needs a
# toolchain that verifier does not control. L2-class fragilities declared here,
# not closed — examples: `region_lines` stops at the first end marker, so a
# decoy `# --- end substance pin: scenario-10 ---` truncates the hashed text
# (still needs a refreshed pin to stay green); the accept-direction line in
# `enforce_substance`'s mutation-probe caller loop
# (`scripts/tests/compat-stray-guard.sh:842`,
# `region_pin_check "$name" "$const" "$got" "$copy" 2>/dev/null || mutated_fail=1`)
# is a single unguarded command that a one-file edit can neuter; and that loop's
# ledger assertion (`scripts/tests/compat-stray-guard.sh:847`) is the sole catcher
# of a forged `MUTATION_PROBE_RECORD` — neutering it alone stays green on a healthy
# guard. The list is not exhaustive: the reject-direction block just above the
# assertion and the `region_hash_verdict … || return 1` call are the same shape.
# R18 (F1, adversarial round 17) named the third one and changed its disposition:
# `region_set_verdict "$found" "${PINNED_REGIONS:-}" || return 1`
# (`scripts/tests/compat-stray-guard.sh:885`) is a one-file neuter that leaves this
# suite printing `FAIL  pinned-region set changed: …` and still exiting 0 with
# `RESULT: 40 fixture check(s) hold` (measured). The call is not repaired here —
# it stays declared — but the `Stray guard` CI step now rejects a log line
# starting with `FAIL` or `  FAIL` (the two shapes the suites print: a column-0
# `FAIL` from the region checks, and `bad()`'s two-space `  FAIL`), so that mutant reds in
# CI even with the caller neutered (measured), and an un-neutered failure is fatal
# in both places. The net is prefix-literal, deliberately not a substring match:
# the sibling's honest run prints two `  ok` sentences containing the word
# mid-line, so `*FAIL*` would red a passing run (measured). Rewriting the failure
# text to ` fail` or a TAB prefix would slip past, but that is an L2-class
# pinned-suite edit — the declared residue above, not a boundary of this net.
#
# A floor of 0 (or an unset floor) disables the guard from inside, which the
# sibling suite learned the hard way; that is a failure here too. So is a
# zero-padded floor: `00`/`000` are all digits but denote 0, so the floor is
# normalised before it is compared (R2-2), and the below-floor diagnostic prints
# the decimal value rather than `printf`'s octal reading of it (R2-3). Digits
# alone were *not* sufficient either (R3-1): a floor above `9223372036854775807`
# is unparseable as an integer, so the below-floor test is an ordered comparison
# of digit strings and such a floor is a below-floor failure, not a status-2 skip.
MIN_CHECKS=40
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
  'trailing-slash TEST_DIR: assert_no_strays returned 1'
  'trailing-slash TEST_DIR: report names the stray pid'
  'trailing-slash TEST_DIR: stray'
  'untrusted ps (fail): the guard load refused with rc'
  'untrusted ps (fail): the error explains the untrusted census'
  'untrusted ps (empty): the guard load refused with rc'
  'untrusted ps (empty): the error explains the untrusted census'
  'untrusted report probe: assert_no_strays returned 2'
  'untrusted report probe: the error explains the untrusted census'
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
# TODO.md:9892). A pid the guard already reaped can be recycled before this trap
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

# enforce_substance — the substance half of the floor. `enforce_shape` compares
# labels, and a label survives a replaced body (`hits=''` behind the same `ok`,
# or a whole verdict swapped for a dummy), so every region delimited by a
# `substance pin:` marker pair is checksummed byte-for-byte:
#
#   scenario-2   the in-`$TEST_DIR` stray verdict — the spawn, the census call,
#                all three verdicts and the out-of-tree peer survival check.
#                Without it, replacing that body with a forged `rc=1`/`out`
#                behind the identical labels left the suite green (SG-M1,
#                measured by the adversarial reviewer).
#   scenario-10  TODO.md:9759's fix: the input derivation (`compat_src=`, the
#                comment strip) *and* both assertion blocks. Pinning only the
#                two verdict blocks left the line that produces the text they
#                read unpinned, so a forged input — a literal string containing
#                `cleanup_pids` and `reap_scoped_strays`, with
#                `scripts/compat-test.sh` never opened — kept both checksums and
#                stayed green (reviewer 2, R2-1/LIE; measured).
#   scenario-12  the round-6 F2 regression test: the `TEST_DIR="$td12/"` load,
#                the spawn and all three verdicts. Without it, replacing the
#                body with three unconditional `ok` lines carrying the same
#                labels kept the count, the shape and CI green (N1/C1, measured
#                by the adversarial reviewer).
#   scenario-13  the round-6 F3 regression test: both untrusted-`ps` loads and
#                the report-probe invocation, with all six verdicts. Without it,
#                stubbing the outcomes (`out='ERROR: …'; rc=2`) behind the same
#                labels kept the suite green (N1/C2, measured).
#
# An edit inside a pinned region reds until the matching constant below is
# updated, and the failure text prints the value to paste. The pins add no
# `ok`/`bad` call of their own, so they can never move the fixture count — or
# the ci.yml literal that pins it — by themselves.
#
# The enforcer is pinned too (N5, adversarial round 4): the list of guarded
# regions is derived from the `substance pin:` markers actually present and must
# equal `PINNED_REGIONS`, the number of regions actually checksummed must equal
# `PINNED_REGION_COUNT`, and every hash is taken from the file the enforcer was
# started from, never from `$self`. Emptying the loop, dropping or repeating a
# name, deleting a marker or reassigning `self` all red instead of silently
# shrinking the guarded set.
SCEN2_REGION_SHA='672f7e60063731363e7b1583a7f415cee46b5c2fc2710f82792df75f9cb18886'
SCEN10_REGION_SHA='ee09f91197512d44712a948ef3ea6ae939daefb30332eff72bdf4123c8a713ce'
SCEN12_REGION_SHA='6742cb4ea68f2ecb9baa13910fd0ba250507e44368935085711b4cd68d8fa159'
SCEN13_REGION_SHA='071ade36c23aa45df0908f633a3e2f9686574fd672c9d83796526bdf0db24a67'
PINNED_REGIONS='scenario-2 scenario-10 scenario-12 scenario-13'
PINNED_REGION_COUNT=4
# Known vectors the hashing tool must reproduce, and the path the read-path
# canary asks for (it must not exist).
ABC_SHA256='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
EMPTY_SHA256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
CANARY_MISSING_PATH='/nonexistent-enforcer-canary'
# Resolve the hashing tool to an absolute path and prove it with a known vector.
# `command -v sha256sum` honours a shell function first and then $PATH, so a fake
# `sha256sum` — a function defined in this file, or a directory prepended to
# PATH — could return a pinned digest for bytes that changed while every check
# "passed" (adversarial round 9, F3). An absolute path cannot be shadowed that
# way, and a wrong tool fails the vector instead of being trusted.
#
# Round 14 (F1, adversarial round 13): the probe's digest used to be extracted
# by piping the hasher through an unqualified `awk '{print $1}'`. A directory
# prepended to PATH holding an `awk` that answers only that exact invocation —
# mapping the drifted digests back to the pins — left a genuine regression in
# this very file undetected while the step still printed `pins verified 4/4` and
# exited 0 (measured). `awk` is gone from the digest path: `${probe%% *}` is a
# shell expansion, so nothing PATH resolves stands between the absolute hasher
# and its comparison. The same removal is applied at every other digest read
# below (`region_sha`, the content-mutation probe) and in `ci.yml`.
find_hash_tool() {
  local cand probe
  for cand in /usr/bin/sha256sum /bin/sha256sum /sbin/sha256sum /usr/sbin/sha256sum /usr/local/bin/sha256sum; do
    [ -x "$cand" ] || continue
    probe=$(printf 'abc' | "$cand" 2>/dev/null)
    [ "${probe%% *}" = "$ABC_SHA256" ] || continue
    printf '%s\n' "$cand"
    return 0
  done
  for cand in /usr/bin/shasum /bin/shasum /usr/local/bin/shasum; do
    [ -x "$cand" ] || continue
    probe=$(printf 'abc' | "$cand" -a 256 2>/dev/null)
    [ "${probe%% *}" = "$ABC_SHA256" ] || continue
    printf '%s -a 256\n' "$cand"
    return 0
  done
  return 1
}
HASH_TOOL=$(find_hash_tool) || HASH_TOOL=''
# The hasher's own ledger (round 12, R10-1). `REGION_HASHED` counts the digests
# `region_sha` actually computed and `REGION_HASHED_RECORD` is the `name=digest`
# list it produced, so a caller that bypasses the real `run_pin_checks`
# invocation — even by assigning the count it expects — leaves the ledger short
# and reds `region_hash_verdict`. `region_sha` is only ever called directly from
# this shell (never in a `$( … )` subshell), so the writes escape.
REGION_HASHED=0
REGION_HASHED_RECORD=''
REGION_SHA_VALUE=''
# The content-mutation probe's own ledger (round 13, R12-3). `mutation_probe`
# records each probe it *completed* — i.e. after it saw the honest comparison
# reject the mutated copy and accept it against that copy's real digest — and
# `enforce_substance` asserts the ledger, so replacing the probe's body with
# `return 0` reds in-suite instead of silently dropping the probe (the file pin
# in ci.yml is the outer defence, not the only one).
MUTATION_PROBES=0
MUTATION_PROBE_RECORD=''

# The lines of a `substance pin: $1` region in file `$2`, printed exactly as
# `sed -n "/^# --- substance pin: $1 /,/^# --- end substance pin: $1 ---/p"`
# would: from the first start marker through the first end marker (both
# inclusive), through EOF when there is no end marker, and nothing at all when
# there is no start marker. Round 14 (F1): the region text used to reach the
# hasher through a PATH-resolved `sed`, which a shadow earlier on PATH could
# point at a frozen pristine copy and so hash the wrong bytes. `read`, `case`
# and `printf` are shell builtins, so no PATH lookup stands between a pinned
# file's bytes and the absolute, vector-proven hasher. Always returns 0: an
# unreadable file yields no lines, which hashes to `$EMPTY_SHA256` and is caught
# by the callers (the read-path canary and the empty-digest check in the probe).
region_lines() {   # $1 = region name, $2 = file to read
  local name=$1 file=$2 line started=0
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$started" -eq 0 ]; then
      case $line in
        "# --- substance pin: $name "*) started=1 ;;
        *) continue ;;
      esac
    fi
    printf '%s\n' "$line"
    case $line in
      "# --- end substance pin: $name ---") return 0 ;;
    esac
  done < "$file"
  return 0
}

region_sha() {   # $1 = region name, spelled as between the `substance pin:` markers
  # $2 = the file to read the region from. The *caller* chooses the path, so the
  # callee cannot report an input of its own choosing (round 9, F3), and the
  # read-path canary in `enforce_substance` proves the read follows it. The
  # digest is returned in `REGION_SHA_VALUE` rather than on stdout (round 12) so
  # the callers stay in the current shell and the ledger above is real.
  local name=$1 file=$2 hash out
  REGION_SHA_VALUE=''
  if [ -z "${HASH_TOOL:-}" ]; then
    printf 'FAIL  no sha256 tool at an absolute path (need sha256sum or shasum); cannot check the %s substance pin\n' "$name" >&2
    return 1
  fi
  if [ -z "$file" ]; then
    printf 'FAIL  no file given to checksum the %s substance pin from\n' "$name" >&2
    return 1
  fi
  # Round 14 (F1): `region_lines` (builtins) replaces `sed`, and `${out%% *}`
  # replaces `awk`, so this read is PATH-free end to end.
  # shellcheck disable=SC2086  # $HASH_TOOL is the word-split "<abs path> -a 256"
  out=$(region_lines "$name" "$file" | $HASH_TOOL)
  hash=${out%% *}
  REGION_HASHED=$((REGION_HASHED + 1))
  REGION_HASHED_RECORD="${REGION_HASHED_RECORD:+$REGION_HASHED_RECORD }${name}=${hash}"
  REGION_SHA_VALUE=$hash
  return 0
}
# --- the enforcer's comparisons, in one place each ----------------------------
# The real checks and the canary in `enforce_substance` both go through these,
# so an edit that makes a comparison trivially true (`got=$want`, `if false`,
# `|| true`) stops the canary from seeing the mismatch it injects and the suite
# reds. This is the whole point: the pins are worthless if the code that reads
# them can be neutered while the summary stays green (adversarial round 5, F7).
region_set_mismatch() { [ "$1" != "$2" ]; }
region_count_mismatch() { [ "$1" -ne "$2" ]; }

# $1 = region name, $2 = pinned constant name (for the diagnostic), $3 = the
# pinned expectation, $4 = the file to read the region from (defaults to
# `SELF_REAL`, the file the enforcer was started from). The path comes from
# `SELF_REAL`, frozen at startup, never from `$self`, so reassigning `self` after
# startup cannot move the bytes being read (round 9, F3) — and that reassignment
# is itself a failure below. The content-mutation probe passes a deliberately
# mutated copy so this same comparison is exercised against bytes the pin must
# reject (round 12, M3).
region_pin_check() {
  local name=$1 const=$2 want=$3 file=${4:-${SELF_REAL:-}} got
  if [ -z "${SELF_REAL:-}" ] || [ "${self:-}" != "${SELF_REAL:-}" ]; then
    printf 'FAIL  %s substance pin: the enforcer path changed after startup (self=%s, bound at startup=%s)\n' \
      "$name" "${self:-<unset>}" "${SELF_REAL:-<unset>}" >&2
    return 1
  fi
  region_sha "$name" "$file" || return 1
  got=$REGION_SHA_VALUE
  if [ "$got" != "$want" ]; then
    printf 'FAIL  %s region changed: sha256 %s, pinned %s\n' \
      "$name" "${got:-<none>}" "$want" >&2
    printf '      deliberate edit? set %s in %s to the value above\n' \
      "$const" "${self:-this script}" >&2
    return 1
  fi
  return 0
}

# $1 = the marker set actually found, $2 = the expected set. Prints the FAIL and
# returns 1 on a mismatch. The canary below calls this same function with a
# deliberately wrong pair, so an edit that makes the comparison trivially true
# (`if false`, `|| true`, `return 0` first) stops the canary from seeing its
# injected mismatch and reds the suite.
region_set_verdict() {
  if region_set_mismatch "$1" "$2"; then
    printf 'FAIL  pinned-region set changed: markers name [%s], expected [%s]\n' \
      "$1" "${2:-<unset>}" >&2
    printf '      restore the `substance pin:` markers (or move PINNED_REGIONS with them) in %s\n' \
      "${self:-this script}" >&2
    return 1
  fi
  return 0
}

# $1 = the number of regions actually checksummed, $2 = the expected count.
# Fails closed and visibly on a missing or non-numeric expectation (F2): the
# compare must never expand unbound inside the EXIT trap.
region_count_verdict() {
  case ${2:-} in
    '' | *[!0-9]*)
      printf 'FAIL  the pinned-region count is missing or not a number (PINNED_REGION_COUNT=%s); the count gate cannot run\n' \
        "${2:-<unset>}" >&2
      return 1
      ;;
  esac
  if region_count_mismatch "$1" "$2"; then
    printf 'FAIL  substance check verified %s region(s), expected %s [%s]\n' \
      "$1" "$2" "${PINNED_REGIONS:-<unset>}" >&2
    return 1
  fi
  return 0
}

# $1 = the `name=digest` record `region_sha` accumulated, $2 = the record the
# pinned entries imply. Round 12, R10-1: a caller can assign a *count*
# (`PIN_CHECKED=$PINNED_REGION_COUNT` was the round-10 bypass), so the count
# alone cannot prove the loop ran — this record can only be produced by hashing
# every pinned region, and a bypass of the real `run_pin_checks` invocation
# leaves it empty.
region_hash_verdict() {
  if region_set_mismatch "$1" "$2"; then
    printf 'FAIL  the region hasher recorded [%s], expected [%s]: the real pin loop did not hash every pinned region\n' \
      "${1:-<none>}" "${2:-<none>}" >&2
    return 1
  fi
  return 0
}

# $1 = region name, $2 = pinned constant name, $3 = the pinned digest, $4 = a
# directory to build the mutated copy in. Round 12 (M3): the shape-identical pin
# canary only ever feeds a `want` outside the pinned set, so it cannot see a
# comparison that returns a verdict without reading the bytes. This probe
# requires (a) the region's digest to differ between the real file and a copy
# that differs by one byte, (b) the honest comparison to reject that copy, and
# (c) it to accept the same copy against the digest the copy really has.
# Round 13 (R12-4): that third digest is computed here, independently of
# `region_sha`, and `region_sha` is required to agree with it — otherwise a
# `region_sha` keyed on the path it is handed (the real file → the pinned
# constant, anything else → empty) satisfies (a) and (b) and is only caught by
# (c), which is exactly the hole this closes. (c) also catches a constant keyed
# on the region *name* rather than the path, for every region this probe walks —
# round 14 (F2) walks all four pinned ones, so a plausible constant for
# scenario-10 or scenario-12 is no longer outside the probe's reach. A `got=$want`
# comparison fails (b), and rejecting everything fails (c). Round 13 (R12-3): a
# completed probe is recorded in the ledger above, which `enforce_substance`
# asserts. Round 14 (F3): that ledger now carries each copy's *real digest*, and
# the caller re-hashes the copies on disk and re-runs the comparison against them,
# so recording the ledger without doing the work reds. Round 14 (F1): the copy is
# built and read with shell builtins only, so no PATH-resolved `sed` mints the
# bytes either.
mutation_probe() {
  local name=$1 const=$2 want=$3 dir=$4 copy honest reported mutated line
  if [ -z "${SELF_REAL:-}" ]; then
    printf 'FAIL  enforcer canary: cannot run the content-mutation probe without the enforcer path\n' >&2
    return 1
  fi
  if [ -z "${HASH_TOOL:-}" ]; then
    printf 'FAIL  enforcer canary: cannot run the content-mutation probe without a sha256 tool\n' >&2
    return 1
  fi
  copy=$dir/mutated-$name.sh
  if [ ! -r "$SELF_REAL" ]; then
    printf 'FAIL  enforcer canary: cannot read %s to build the one-byte-different %s copy for the content probe\n' \
      "$SELF_REAL" "$name" >&2
    return 1
  fi
  # `sed "s/^# --- substance pin: ${name} /&mutated /"`, in the shell: insert
  # `mutated ` after the start marker's name on its own line only.
  while IFS= read -r line || [ -n "$line" ]; do
    case $line in
      "# --- substance pin: $name "*)
        printf '%s\n' "# --- substance pin: $name mutated ${line#"# --- substance pin: $name "}" ;;
      *) printf '%s\n' "$line" ;;
    esac
  done < "$SELF_REAL" > "$copy"
  region_sha "$name" "$SELF_REAL" || return 1
  honest=$REGION_SHA_VALUE
  region_sha "$name" "$copy" || return 1
  reported=$REGION_SHA_VALUE
  # The copy's real digest, taken the same way but *not* through `region_sha`, so
  # a self-consistent fake has nothing to agree with.
  # shellcheck disable=SC2086  # $HASH_TOOL is the word-split "<abs path> [-a 256]"
  mutated=$(region_lines "$name" "$copy" | $HASH_TOOL)
  mutated=${mutated%% *}
  if [ -z "$mutated" ]; then
    printf 'FAIL  enforcer canary: cannot compute the %s copy digest for the content probe\n' "$name" >&2
    return 1
  fi
  if [ "$honest" = "$mutated" ]; then
    printf 'FAIL  enforcer canary: the %s region and its one-byte-different copy both hash to %s; the copy is not different\n' \
      "$name" "${honest:-<none>}" >&2
    return 1
  fi
  if [ "$reported" != "$mutated" ]; then
    printf 'FAIL  enforcer canary: region_sha reported %s for the %s copy, but that copy really hashes to %s; the hasher is not reading the bytes of the path it is given\n' \
      "${reported:-<none>}" "$name" "$mutated" >&2
    return 1
  fi
  if region_pin_check "$name" "$const" "$want" "$copy" 2>/dev/null; then
    printf 'FAIL  enforcer canary: the comparison accepted a one-byte-different %s copy as matching its pin; the pin is not bound to the bytes\n' "$name" >&2
    return 1
  fi
  if ! region_pin_check "$name" "$const" "$mutated" "$copy" 2>/dev/null; then
    printf 'FAIL  enforcer canary: the comparison rejected the mutated %s copy even against the digest that copy really has; the comparison is not bound to the path it is given\n' "$name" >&2
    return 1
  fi
  # Recorded only now, after the copy was built, hashed and compared in both
  # directions — and with the digest, not a bare name, so the caller can tell a
  # ledger written without the work from one the probe earned (round 14, F3).
  MUTATION_PROBES=$((MUTATION_PROBES + 1))
  MUTATION_PROBE_RECORD="${MUTATION_PROBE_RECORD:+$MUTATION_PROBE_RECORD }${name}=${mutated}"
  return 0
}

# One checked region, its mismatch counted. Both the real loop and the canary
# call this, so swallowing a mismatch (`|| true`) or dropping the call leaves
# `PIN_FAILS` unchanged and the canary reds. The *number* of regions checked is
# not counted here (round 12, R10-1): that ledger lives inside `region_sha`, so
# no call site can spoof the count without actually hashing.
record_pin_check() {   # $1 = region name, $2 = constant name, $3 = expectation
  region_pin_check "$1" "$2" "$3" || PIN_FAILS=$((PIN_FAILS + 1))
}

# Shape-identical wrong value for the pin canary: shift every hex digit by one
# (a→b, … f→0), so the injected expectation is a 64-character lowercase hex
# digest exactly like every real pin. A comparison that whitelists the canary's
# sentinel, or rejects anything that is not 64 hex characters, cannot satisfy
# both of the canary's directions this way (adversarial round 9, F2).
flip_hex() { printf '%s' "$1" | tr '0123456789abcdef' '123456789abcdef0'; }

# $1 = newline-separated "name const want" entries, checked one per line. Both
# the injected canary entry and the real pinned set go through this one loop, so
# neutering its call to `record_pin_check` — replacing it with a bare counter
# bump, say — leaves the canary's injected mismatch unrecorded and reds the suite
# (adversarial round 9, F1: the canary used to call `record_pin_check` directly
# and so never exercised this call site). A here-doc, not a pipe: `while … done |
# …` would run the loop in a subshell and the counters would never escape.
run_pin_checks() {
  local name const want
  while IFS=' ' read -r name const want; do
    [ -n "$name" ] || continue
    record_pin_check "$name" "$const" "$want"
  done <<EOF
$1
EOF
}

enforce_substance() {
  local name const want found region_entries expected_record mutation_dir
  local canary_right canary_wrong canary_missing
  local canary_hashed canary_fails canary_ok_hashed canary_ok_fails
  local line rest copy got mutated_record mutated_fail
  # F2 (adversarial round 5): every guarded read below uses `${var:-}` so that a
  # deleted definition reaches an explicit FAIL instead of expanding unbound.
  # Under `set -u` an unbound expansion *inside the EXIT trap* prints its error,
  # leaves bash exiting 0 and silently skips the gate (measured: delete
  # `PINNED_REGION_COUNT` → rc 0, CI green). The trap calls are also wrapped in
  # subshells so any future fatal error becomes a nonzero rc rather than exit 0.
  PIN_FAILS=0
  # The marker census, in the shell (round 14, F1): the `sed`+`tr` pipeline that
  # used to build this ran through PATH, so a shadowed `sed` could forge the
  # region set while a marker was deleted. `read`/`case` are builtins.
  found=''
  if [ -n "${SELF_REAL:-}" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      case $line in
        '# --- substance pin: '*)
          rest=${line#'# --- substance pin: '}
          found="${found}${rest%% *} "
          ;;
      esac
    done < "$SELF_REAL"
  fi
  found=${found% }
  # --- the enforcer canary (round 5 F7; loop-driven, round 9 F1/F2; 12) --------
  # The pins only mean something while the code that reads them works, and that
  # code lives here in the same unpinned prologue. So the canary injects a
  # *shape-identical* wrong expectation — the real pin with every hex digit
  # shifted by one — through the same loop the pinned set uses, and requires both
  # outcomes: the wrong value must be recorded as a mismatch and the real value
  # must be accepted. Neutering the comparison (`got=$want`, `if false`),
  # whitelisting a sentinel shape, rejecting everything, or bypassing the loop's
  # call site all leave one of the outcomes wrong and red the suite here. The
  # hasher's own ledger is asserted too, so a path that reports a verdict
  # without reading the file reds even when the verdict looks right.
  canary_right=${SCEN2_REGION_SHA:-}
  canary_wrong=$(flip_hex "$canary_right")
  PIN_FAILS=0
  REGION_HASHED=0
  REGION_HASHED_RECORD=''
  run_pin_checks "scenario-2 SCEN2_REGION_SHA ${canary_wrong}" 2>/dev/null
  canary_hashed=$REGION_HASHED
  canary_fails=$PIN_FAILS
  PIN_FAILS=0
  REGION_HASHED=0
  REGION_HASHED_RECORD=''
  run_pin_checks "scenario-2 SCEN2_REGION_SHA ${canary_right}" 2>/dev/null
  canary_ok_hashed=$REGION_HASHED
  canary_ok_fails=$PIN_FAILS
  if [ "$canary_hashed" -ne 1 ] || [ "$canary_fails" -ne 1 ]; then
    printf 'FAIL  enforcer canary: an injected wrong pin was not hashed and recorded as a mismatch (hashed=%s, fails=%s); the region comparison is neutered, the loop call site is bypassed or the hasher never ran\n' \
      "$canary_hashed" "$canary_fails" >&2
    return 1
  fi
  if [ "$canary_ok_hashed" -ne 1 ] || [ "$canary_ok_fails" -ne 0 ]; then
    printf 'FAIL  enforcer canary: a correct pin was not hashed and accepted (hashed=%s, fails=%s); the region comparison no longer accepts matching digests\n' \
      "$canary_ok_hashed" "$canary_ok_fails" >&2
    return 1
  fi
  # The same comparison probed by return status rather than by the ledger the
  # loop maintains, so asserting that ledger in the prologue is not enough.
  REGION_HASHED=0
  if region_pin_check scenario-2 SCEN2_REGION_SHA "$canary_wrong" 2>/dev/null; then
    printf 'FAIL  enforcer canary: the region comparison accepted an injected wrong pin; it is neutered\n' >&2
    return 1
  fi
  if [ "$REGION_HASHED" -ne 1 ]; then
    printf 'FAIL  enforcer canary: the rejected wrong pin was not hashed (hasher ran %s time(s), expected 1)\n' \
      "$REGION_HASHED" >&2
    return 1
  fi
  REGION_HASHED=0
  if ! region_pin_check scenario-2 SCEN2_REGION_SHA "$canary_right" 2>/dev/null; then
    printf 'FAIL  enforcer canary: the region comparison rejected a correct pin; it rejects everything\n' >&2
    return 1
  fi
  if [ "$REGION_HASHED" -ne 1 ]; then
    printf 'FAIL  enforcer canary: the accepted correct pin was not hashed (hasher ran %s time(s), expected 1)\n' \
      "$REGION_HASHED" >&2
    return 1
  fi
  # The hashing read must follow the path it is given: a read redirected to a
  # frozen pristine copy would hash that copy and leave every pin inert while the
  # report stayed honest (round 9, R9-2). A path that cannot exist must hash to
  # the digest of empty input; a redirected read returns the copy's digest. This
  # canary proves the *redirect* case only; the content-mutation probe above is
  # what proves a name-keyed constant cannot satisfy the pins (round 14, F4).
  REGION_HASHED=0
  region_sha scenario-2 "$CANARY_MISSING_PATH" 2>/dev/null
  canary_missing=$REGION_SHA_VALUE
  if [ "$canary_missing" != "$EMPTY_SHA256" ]; then
    printf 'FAIL  enforcer canary: hashing does not follow the path it is given (missing-file digest %s, expected %s); a redirected read would not be detected\n' \
      "${canary_missing:-<none>}" "$EMPTY_SHA256" >&2
    return 1
  fi
  if [ "$REGION_HASHED" -ne 1 ]; then
    printf 'FAIL  enforcer canary: the missing-path probe did not hash the path it was given\n' >&2
    return 1
  fi
  # --- content-mutation probe (round 12, M3; ledger round 13, R12-3) ----------
  # `$WORK` is already removed by `cleanup_all` before the enforcers run, so the
  # probe builds its own directory under the system temp dir.
  mutation_dir=$(mktemp -d "${TMPDIR:-/tmp}/enforcer-mutation.XXXXXX") || mutation_dir=''
  if [ -z "$mutation_dir" ]; then
    printf 'FAIL  enforcer canary: cannot create the content-mutation probe directory\n' >&2
    return 1
  fi
  MUTATION_PROBES=0
  MUTATION_PROBE_RECORD=''
  # Round 14 (F2): all four pinned regions, not the two round 13 exercised. The
  # subset left a `region_sha` that fabricates a digest for scenario-10 and
  # scenario-12 only satisfied by the paths the probe never walked.
  if ! mutation_probe scenario-2 SCEN2_REGION_SHA "${SCEN2_REGION_SHA:-}" "$mutation_dir" ||
    ! mutation_probe scenario-10 SCEN10_REGION_SHA "${SCEN10_REGION_SHA:-}" "$mutation_dir" ||
    ! mutation_probe scenario-12 SCEN12_REGION_SHA "${SCEN12_REGION_SHA:-}" "$mutation_dir" ||
    ! mutation_probe scenario-13 SCEN13_REGION_SHA "${SCEN13_REGION_SHA:-}" "$mutation_dir"; then
    rm -rf "$mutation_dir"
    return 1
  fi
  # The probe's own ledger, checked *here* rather than trusted (round 13, R12-3;
  # round 14, F3). Each entry is `name=digest`, where the digest is the copy the
  # probe built; this caller recomputes those digests from the copies still on
  # disk — through `region_lines`+`$HASH_TOOL`, not `region_sha`, so the check is
  # independent of the function under test — and re-runs the pin comparison
  # against each copy in both directions (reject the pinned digest, accept the
  # copy's real one). A `return 0` body, a probe that skips its assertions, a
  # call that was dropped, or a ledger written at the top of the function without
  # hashing the copies all leave this red — the file pin in ci.yml is the outer
  # defence, not the only one.
  mutated_record=''
  mutated_fail=0
  # shellcheck disable=SC2086  # intentional word split: PINNED_REGIONS is a name list
  for name in ${PINNED_REGIONS:-}; do
    case $name in
      scenario-2)  const=SCEN2_REGION_SHA;  want=${SCEN2_REGION_SHA:-} ;;
      scenario-10) const=SCEN10_REGION_SHA; want=${SCEN10_REGION_SHA:-} ;;
      scenario-12) const=SCEN12_REGION_SHA; want=${SCEN12_REGION_SHA:-} ;;
      scenario-13) const=SCEN13_REGION_SHA; want=${SCEN13_REGION_SHA:-} ;;
      *) continue ;;
    esac
    copy=$mutation_dir/mutated-$name.sh
    # shellcheck disable=SC2086  # $HASH_TOOL is the word-split "<abs path> [-a 256]"
    got=$(region_lines "$name" "$copy" | $HASH_TOOL)
    got=${got%% *}
    mutated_record="${mutated_record:+$mutated_record }${name}=${got}"
    region_pin_check "$name" "$const" "$got" "$copy" 2>/dev/null || mutated_fail=1
    if region_pin_check "$name" "$const" "$want" "$copy" 2>/dev/null; then
      mutated_fail=1
    fi
  done
  if [ "$MUTATION_PROBES" -ne 4 ] || [ "$MUTATION_PROBE_RECORD" != "$mutated_record" ] || [ "$mutated_fail" -ne 0 ]; then
    printf 'FAIL  enforcer canary: the content-mutation probe recorded [%s] (%s completed) and the copies this caller independently re-hashed imply [%s]; the probe did not run against all four pinned regions, its ledger was written without hashing the copies, or the pin comparison did not reject the mutated copies and accept their real digests\n' \
      "${MUTATION_PROBE_RECORD:-<none>}" "$MUTATION_PROBES" "${mutated_record:-<none>}" >&2
    rm -rf "$mutation_dir"
    return 1
  fi
  rm -rf "$mutation_dir"
  # Same functions the real checks below call, driven with a deliberately wrong
  # expectation in each direction; their diagnostics are the point of the
  # exercise, so they are discarded here.
  if region_set_verdict "$found" "$found" 2>/dev/null; then :; else
    printf 'FAIL  enforcer canary: the pinned-region set comparison is neutered\n' >&2
    return 1
  fi
  if region_set_verdict "$found" "${found}-enforcer-canary" 2>/dev/null; then
    printf 'FAIL  enforcer canary: the pinned-region set comparison is neutered\n' >&2
    return 1
  fi
  if region_count_verdict 1 1 2>/dev/null; then :; else
    printf 'FAIL  enforcer canary: the count comparison is neutered\n' >&2
    return 1
  fi
  if region_count_verdict 1 2 2>/dev/null; then
    printf 'FAIL  enforcer canary: the count comparison is neutered\n' >&2
    return 1
  fi
  if region_hash_verdict 'a=1' 'a=1' 2>/dev/null; then :; else
    printf 'FAIL  enforcer canary: the hash-record comparison is neutered\n' >&2
    return 1
  fi
  if region_hash_verdict 'a=1' 'a=2' 2>/dev/null; then
    printf 'FAIL  enforcer canary: the hash-record comparison is neutered\n' >&2
    return 1
  fi
  # Positive evidence that the canary ran, printed only after it passed; the
  # `health` CI step greps this exact literal, so deleting or neutering the
  # canary reds CI even when the summary looks intact.
  printf 'enforcer canary: injected mismatch detected, injected count mismatch detected\n'
  region_set_verdict "$found" "${PINNED_REGIONS:-}" || return 1
  # The pinned set goes through the same loop the canary exercised above. The
  # entries are built first so the region check itself stays one call site
  # (round 9, F1); the expected `name=digest` record is built beside them, so the
  # hasher's own ledger can be checked against what the pins imply (round 12,
  # R10-1) — a copied count cannot produce that record.
  region_entries=''
  expected_record=''
  # shellcheck disable=SC2086  # intentional word split: PINNED_REGIONS is a name list
  for name in ${PINNED_REGIONS:-}; do
    case $name in
      scenario-2)  const=SCEN2_REGION_SHA;  want=${SCEN2_REGION_SHA:-} ;;
      scenario-10) const=SCEN10_REGION_SHA; want=${SCEN10_REGION_SHA:-} ;;
      scenario-12) const=SCEN12_REGION_SHA; want=${SCEN12_REGION_SHA:-} ;;
      scenario-13) const=SCEN13_REGION_SHA; want=${SCEN13_REGION_SHA:-} ;;
      *)
        printf 'FAIL  unguarded region name in PINNED_REGIONS: %s\n' "$name" >&2
        return 1
        ;;
    esac
    region_entries="${region_entries}${name} ${const} ${want}
"
    expected_record="${expected_record:+$expected_record }${name}=${want}"
  done
  PIN_FAILS=0
  REGION_HASHED=0
  REGION_HASHED_RECORD=''
  run_pin_checks "$region_entries"
  if [ "$PIN_FAILS" -ne 0 ]; then
    printf 'FAIL  %s pinned region(s) changed; see the diagnostics above\n' "$PIN_FAILS" >&2
    return 1
  fi
  region_count_verdict "$REGION_HASHED" "${PINNED_REGION_COUNT:-}" || return 1
  region_hash_verdict "$REGION_HASHED_RECORD" "$expected_record" || return 1
  # F3/F4 (adversarial round 5): positive evidence that this check ran, printed
  # only on the success path. It names the regions in order and the `health` CI
  # step greps this exact literal, so the expected set lives *outside* the
  # guarded file: `trap - EXIT`, `elif false`, a removed call or a shortened
  # list all leave the line absent and the step red. Nothing else prints it. The
  # count it names is the hasher's own ledger (round 12), not a caller's tally.
  printf 'pinned regions verified %s/%s: %s\n' \
    "$REGION_HASHED" "$PINNED_REGION_COUNT" "$PINNED_REGIONS"
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
              # F2 (adversarial round 5): the enforcers run in subshells so that a
              # `set -u` fatal inside one (an unbound expansion in the trap) yields
              # a nonzero rc here instead of bash exiting 0 with the gate skipped.
              elif ! ( enforce_shape ); then
                rc=1
              elif ! ( enforce_substance ); then
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
# (residue (b) of TODO.md:9892). Nothing here depends on the file's name, so
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
# The verdict body is a `substance pin` region: `enforce_shape` only compares
# labels, so replacing this whole scenario with a dummy `rc=1` behind the same
# labels kept the total, the shape and CI green (SG-M1, measured by the
# adversarial reviewer). Checksumming the region closes that class here the way
# scenario 10's pin closes it there.
# --- substance pin: scenario-2 (checksummed by enforce_substance) ---
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
# --- end substance pin: scenario-2 ---

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
# Residue (b) of TODO.md:9892. The probe child is this same file under a
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
# Residue (c) of TODO.md:9892. A probe that exits 0 with no output used to fall
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
# Residue (a) of TODO.md:9892. The victim is a real synthetic of this run, under
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

# --- scenario 10: the XTCP pre-test cleanup is pid-exact (TODO.md:9759) ------
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
# TODO.md:9759 replaced *two* pattern kills with a pid-exact pair, so the
# scenario has to see both halves inside `run_xtcp_test`: the tracked-pid reaper
# (`cleanup_pids`, TODO.md:9759's first replacement) and the guard's baseline-aware
# census sweep (`reap_scoped_strays`). Pinning only the latter let a mutant that
# deleted the `cleanup_pids` call stay green (measured, reviewer 1).
xtcp_calls=$(printf '%s\n' "$xtcp_body" | grep -cE '^[[:space:]]*cleanup_pids([[:space:]]|$)' || true)
xtcp_sweep=false
case "$xtcp_body" in *'reap_scoped_strays'*) xtcp_sweep=true ;; esac
if $xtcp_sweep && [ "$xtcp_calls" -ge 1 ]; then
  ok 'compat-test.sh: run_xtcp_test sweeps with cleanup_pids and reap_scoped_strays'
else
  bad "compat-test.sh: run_xtcp_test's pre-test cleanup is incomplete (reap_scoped_strays=$xtcp_sweep, cleanup_pids calls=$xtcp_calls) — TODO.md:9759 needs both, one per pkill -f it replaced"
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

# --- scenario 12: a trailing-slash TEST_DIR does not empty the census --------
# F2 (adversarial reviewer): the ownership match is the literal `"$TEST_DIR/"`,
# so a run dir spelled with a trailing slash — `FRP_COMPAT_TEST_DIR=/tmp/x/`,
# which `scripts/compat-test.sh:185` documents — matched `…/x//` and never a
# command line carrying `…/x/`: the census came back empty and
# `assert_no_strays` returned 0 with a live stray. The library normalises the
# spelling once at load, so this drives the real guard with `$td12/` and
# requires the full tooth: a named, reaped stray and rc 1.
# --- substance pin: scenario-12 (checksummed by enforce_substance) ---
hdr 'scenario 12: a trailing-slash TEST_DIR still counts an in-dir stray'
td12="$WORK/run12"
mkdir -p "$td12"
export TEST_DIR="$td12/"
# shellcheck source=/dev/null
source "$LIB"
stray12=$(spawn_fake "$td12/scenario")
LIVE="$LIVE $stray12"
sleep 0.3
out=$(assert_no_strays 2>&1); rc=$?
if [ "$rc" -eq 1 ]; then
  ok 'trailing-slash TEST_DIR: assert_no_strays returned 1'
else
  bad "trailing-slash TEST_DIR: assert_no_strays returned $rc (expected 1) — the spelling emptied the census"
fi
case "$out" in
  *"$stray12"*) ok "trailing-slash TEST_DIR: report names the stray pid $stray12" ;;
  *) bad "trailing-slash TEST_DIR: report does not name the stray pid: $(printf '%s' "$out" | tr '\n' ' ')" ;;
esac
if wait_gone "$stray12"; then
  ok "trailing-slash TEST_DIR: stray $stray12 was reaped"
else
  bad "trailing-slash TEST_DIR: stray $stray12 survived the guard"
fi
# --- end substance pin: scenario-12 ---

# --- scenario 13: an untrusted `ps` in the shipped census is a hard error ----
# F3 (adversarial reviewer): `scenario_strays` read a per-pid `ps` that failed
# (or exited 0 with no output) as "not ours", so the census came back empty and
# a live in-`$TEST_DIR` stray was forgiven — the opposite of the header's
# promise. The first two cases drive the real library with such a `ps` first on
# `PATH`; the baseline census at load has to refuse rather than report nothing.
# --- substance pin: scenario-13 (checksummed by enforce_substance) ---
hdr 'scenario 13: the shipped census refuses a ps probe it cannot trust'
td13="$WORK/run13"
mkdir -p "$td13"
victim13=$(spawn_fake "$td13/scenario")
LIVE="$LIVE $victim13"
# The fake `ps` is only observable if `pgrep` really lists the victim first.
for _ in $(seq 1 50); do
  pgrep -x frps 2>/dev/null | grep -qx "$victim13" && break
  sleep 0.1
done
fakebin13="$WORK/fakebin13"
mkdir -p "$fakebin13"
for kind in fail empty; do
  case $kind in
    fail)  printf '#!/bin/sh\nexit 1\n' > "$fakebin13/ps" ;;
    empty) printf '#!/bin/sh\nexit 0\n' > "$fakebin13/ps" ;;
  esac
  chmod +x "$fakebin13/ps"
  out=$(env PATH="$fakebin13:$PATH" TEST_DIR="$td13" "$BASH_BIN" -c 'source "$1"' _ "$LIB" 2>&1); rc=$?
  if [ "$rc" -ne 0 ]; then
    ok "untrusted ps ($kind): the guard load refused with rc $rc"
  else
    bad "untrusted ps ($kind): the guard loaded and reported an empty census — a live stray was forgiven"
  fi
  case "$out" in
    *'census that cannot be trusted'*) ok "untrusted ps ($kind): the error explains the untrusted census" ;;
    *) bad "untrusted ps ($kind): unexpected output: $(printf '%s' "$out" | tr '\n' ' ')" ;;
  esac
done
# The census itself is trustworthy here; only the exit trap's *report* format
# fails, so `assert_no_strays`'s own per-pid read is the branch under test: a
# live pid it cannot describe must not be read as "the stray went away".
real_ps=$(command -v ps)
{
  printf '#!/bin/sh\n'
  printf 'for a in "$@"; do\n  case "$a" in *ppid*) exit 1 ;; esac\ndone\n'
  printf 'exec %s "$@"\n' "$real_ps"
} > "$fakebin13/ps"
chmod +x "$fakebin13/ps"
export TEST_DIR="$td13"
# shellcheck source=/dev/null
source "$LIB"
victim13b=$(spawn_fake "$td13/late")
LIVE="$LIVE $victim13b"
sleep 0.3
out=$( PATH="$fakebin13:$PATH"; assert_no_strays 2>&1 ); rc=$?
if [ "$rc" -eq 2 ]; then
  ok 'untrusted report probe: assert_no_strays returned 2'
else
  bad "untrusted report probe: assert_no_strays returned $rc (expected 2) — a live stray it could not describe was read as gone"
fi
case "$out" in
  *'census that cannot be trusted'*) ok 'untrusted report probe: the error explains the untrusted census' ;;
  *) bad "untrusted report probe: unexpected output: $(printf '%s' "$out" | tr '\n' ' ')" ;;
esac
# --- end substance pin: scenario-13 ---

# ---------------------------------------------------------------- summary
hdr 'summary'
if [ "$fails" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
else
  printf 'RESULT: %d fixture check(s), %d failure(s) above\n' "$checks" "$fails"
fi
exit "$fails"
