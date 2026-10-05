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
# gate's *own* row is printed (naming `(exit 3)`). The row must be the specific
# one — "some row carries `(exit 3)`" is vacuous, because a bare tree already
# prints two unrelated `(exit 3)` rows. A throwaway tree is enough because
# repo-health.sh runs its sections top to bottom and never exits early on a
# *failed* gate — it reaches the gate under test regardless of the unrelated
# FAILs a bare tree produces.
#
# Later scenarios go past the exit-code mapping, because a positive check alone
# cannot show that the fixture drives the code it claims to: scenario 4 builds
# the stub inputs that let all four `.rs` walks run and then reverts each walk's
# fall-through in the tree's own copy of the script, one at a time, so the checks
# are shown to red on the right edit; scenario 5 is the clean-tree negative
# control for scenario 1's row; scenario 6 asserts the integration-test-dir
# metric, whose `scripts/tests/` blind spot is why it exists; scenario 7 pins
# site 4's crate-root row with a cross-crate alias (and with the count-inert
# mutation that re-raises it); scenario 8 pins the kernel's symlink-chain refusal
# that makes the in-script `readlink` bound unreachable; scenario 9 shows a failed
# fixture setup stops the run — and pins that **nothing** below it runs at all;
# scenario 10 pins the walk-error path against the false "no .rs files"
# accusation (with both mutations of that guard); scenario 11 pins containment's
# separator with a sibling whose name starts with the crate name.
#
# Self-contained: no network, no dependence on this repo's contents (the tree is
# built from scratch and only the script under test is copied in), and the
# temporary tree is removed on exit.
#
# Usage: bash scripts/tests/repo-health-fixtures.sh
#        (also correct when the harness itself is invoked through a symlink)
set -uo pipefail

# --- self-defence: assert a floor on every exit path --------------------------
# This suite is the only thing that pins `scripts/repo-health.sh`, so a suite
# that silently stops checking must not exit green: `exit "$fail"` alone is happy
# with `RESULT: 0 fixture check(s) hold`. The trap is installed here — before the
# path resolution, the two preflights and the first `ok`/`bad` — so an early
# `exit 0` anywhere below it still has to answer to the floor. `MIN_CHECKS` is
# the measured check count of a green run; with an exact floor, emptying any
# scenario body drops the count below it and reds (TODO.md:9856).
#
# Three limits are stated rather than hidden:
#   * a floor of 0 (or an unset floor, or a zero-padded all-zero floor such as
#     `00`/`000`, which denote 0 but are still all digits) would disable the
#     guard from inside, so each is itself a failure: leading zeros are stripped
#     before the comparison, so no spelling of zero slips past the `0)` arm, and
#     diagnostics print the decimal value — `printf '%d'` reads `032` as octal
#     26, so it is not used (R2-2/R2-3);
#   * the floor is never compared with `[ … -lt … ]` on the values: a floor that
#     is not a number is rejected by the `case` arms below — an empty or
#     non-digit `MIN_CHECKS` (and a non-digit `checks`) is a failure, not a skip
#     — and the below-floor test is an ordered comparison of digit strings:
#     length first (`[ "${#checks}" -lt "${#MIN_CHECKS}" ]`, with `-eq` on the
#     lengths to reach the tie-break), then left-to-right at equal length
#     (`[ "$checks" \< "$MIN_CHECKS" ]`). So `-lt` only ever sees two *lengths* —
#     short decimal numbers — and cannot return status 2 on an all-digit floor,
#     however long: a value above `9223372036854775807` is unparseable as an
#     integer but fine as a string, so it lands as an ordinary below-floor
#     failure rather than a skipped branch (R3-1). Length-then-string order is
#     exactly numeric order for digit strings, which is what makes it fail
#     closed;
#   * `exec true` in place of an ordinary exit still skips the EXIT trap — no
#     in-file mechanism can intercept `exec`, and the sibling suite had the same
#     hole. The closure for that one is outside the file: the CI step's own
#     `grep -qF 'RESULT: %d fixture check(s) hold'` plus its `  ok` line count on
#     the captured output (`.github/workflows/ci.yml`), which see a missing
#     RESULT line and a planted one with no assertions behind it.
# A total is also not a *shape*, so `delete N checks, add N dummy ok lines`
# keeps it; the sibling pins its ordered assertion list for that reason. Here the
# assertion set is loop-driven (scenario 4 walks four sites, scenario 10 two
# shapes), and there is no per-scenario tally to pin: `checks` is one run-wide
# counter, initialised to 0 and bumped once by every `ok()` and every `bad()`
# call, so the floor it feeds (`MIN_CHECKS`) bounds the number of assertions
# *attempted* across the whole run — passed and failed alike, with no
# per-scenario breakdown and no relation to the number of `ok` lines printed.
# Pinning an ordered assertion list would need a second instrumented counter per
# scenario, which this suite does not keep; the count is what can be pinned, and
# that residual gap is recorded in the batch-E report.
MIN_CHECKS=32
checks=0
fail=0
tmp=""

ok()  { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fail=1; printf '  FAIL  %s\n' "$1"; }
hdr() { printf '%s\n' "------------------------------------------------------------"; }

# enforce_substance — the substance half of the floor. `MIN_CHECKS` only bounds
# how many assertions ran, and every label is spelled at the call site, so
# replacing a condition kept the total and the suite green: `if true; then` on
# scenario 6's metric check (RH-M2) and `if false; then` on scenario 7's
# aliased-crate-root check (N1/C3), both measured by the adversarial reviewer.
# Every region marked `substance pin:` is therefore checksummed byte-for-byte,
# the way scenarios 2/10/12/13 are in `scripts/tests/compat-stray-guard.sh`; an
# edit inside one reds until the matching constant below is updated, and the
# failure text prints the value to paste. The pins add no `ok`/`bad` call of
# their own, so they cannot move the count — or the ci.yml literal that pins it
# — by themselves. `self` is resolved further down this file, which is fine: the
# check only runs from the EXIT trap, after it is set.
#
# The enforcer is pinned too (N5, adversarial round 4): the list of guarded
# regions is derived from the `substance pin:` markers actually present and must
# equal `PINNED_REGIONS`, the number of regions actually checksummed must equal
# `PINNED_REGION_COUNT`, and every hash is taken from the file the enforcer was
# started from, never from `$self`. Emptying the loop, dropping or repeating a
# name, deleting a marker or reassigning `self` all red instead of silently
# shrinking the guarded set.
#
# Round 12 (same boundary as the stray guard): the count now comes from the
# hasher's own `name=digest` ledger (`region_hash_verdict`), so a caller cannot
# claim a count it did not earn; a content-mutation probe hashes a
# one-byte-different copy of both pinned regions and requires the honest
# comparison to reject it. Round 13 records each completed probe in a ledger
# `enforce_substance` asserts, so gutting the probe reds in-suite, and computes
# the copy's digest independently of `region_sha`, so a path-keyed fake cannot
# satisfy the probe. The `health` CI step pins this file's own sha256 *before*
# running it, so weakening the enforcer here also requires editing
# `.github/workflows/ci.yml`. This suite sources nothing from
# `scripts/lib/compat-stray-guard.sh`, so — unlike the stray-guard step — no
# library pin is needed here. The honest claim is that it catches careless
# single-region edits and makes an edit to the guard itself a two-file change a
# reviewer sees — not that it prevents pin removal: an edit here plus a refreshed
# `SCEN*_REGION_SHA` (L2), or a forged summary and evidence block (L1), is still
# green. Those stay declared residues.
#
# Round 14 (F1): the digest *read* is PATH-free by construction — `region_lines`
# uses `read`/`case`/`printf`, `${x%% *}` splits the hasher's output and
# `$HASH_TOOL` is absolute and vector-proven — so a shadowed `awk` or `sed` can no
# longer mint a region's bytes or its digest. Round 14 (F3) records the copy's
# real digest in the probe's ledger and has `enforce_substance` re-hash the copies
# and re-run the comparison against each, so a ledger written without the work
# reds instead of staying green. Both are demonstrated, not asserted: on the
# pre-fix tree an `awk` shim answering only `{print $1}` kept a drifted region
# green and a ledger written before the work stayed green; each reds now.
#
# What remains is the declared boundary. (R14-a) this suite's own inspections of
# other files (`grep`, and the two `awk` parses of `$out`) still resolve through
# PATH, so a shim can make one scenario's assertion vacuous — a weakened scenario,
# and a possible false negative for the regression that scenario exists to catch,
# but never a defeated pin. It is reachable and accepted: an unpinned in-repo
# file, or the `scripts/repo-health.sh` step that runs before this one, can put
# a shim earlier on `$PATH` (GitHub's `$GITHUB_PATH` persists it into later
# steps).
# (R14-b) `flip_hex`'s `tr` and the `mktemp` probe directory are PATH-resolved but
# fail closed: a `tr` that returns its input collapses the canary's injected wrong
# pin onto the correct one and reds, and a directory from `mktemp` cannot forge
# the ledger the caller re-derives from the copies. (R14-c) a shadowed `bash`
# (the interpreter) or a replaced absolute `/usr/bin/sha256sum` owns the process
# and is out of scope. L2-class fragilities declared here, not closed — examples:
# `region_lines` stops at the first end marker, so a decoy
# `# --- end substance pin: scenario-6 ---` truncates the hashed text; the
# accept-direction line in the mutation-probe caller loop
# (`scripts/tests/repo-health-fixtures.sh:623`,
# `region_pin_check "$name" "$const" "$got" "$copy" 2>/dev/null || mutated_fail=1`)
# is a single unguarded command a one-file edit can neuter; and that loop's ledger
# assertion (`scripts/tests/repo-health-fixtures.sh:628`) is the sole catcher of a
# forged `MUTATION_PROBE_RECORD` — neutering it alone stays green on a healthy
# guard. The list is not exhaustive: the reject-direction block just above the
# assertion and the `region_hash_verdict … || return 1` call are the same shape.
# Each still needs the pin refreshed to stay green.
SCEN6_REGION_SHA='7d31d2b613e1e578c7050a5328cb677f4aac2eba1c6d9a7248f0216d1dd06af7'
SCEN7_REGION_SHA='941be4f7805b74ff79b691e463f91dd011a1b549cd17995f09542ff8d3f40500'
PINNED_REGIONS='scenario-6 scenario-7'
PINNED_REGION_COUNT=2
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
# Round 14 (F1): that vector proof used to be read back through an unqualified
# `awk '{print $1}'`, so a directory prepended to PATH holding an `awk` that
# answers only that exact invocation could make a wrong candidate look right (or,
# more to the point, make every digest below look like its pin) while the step
# still printed its success line and exited 0 (measured on the sibling suite).
# `${probe%% *}` is a shell expansion: it performs no PATH lookup, so nothing
# resolves between the absolute, vector-proven hasher and its comparison. The
# same removal is applied to `region_sha` and the content-mutation probe below.
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
    printf 'FAIL  no sha256 tool at an absolute path (need sha256sum or shasum); cannot check the %s region\n' "$name" >&2
    return 1
  fi
  if [ -z "$file" ]; then
    printf 'FAIL  no file given to checksum the %s region from\n' "$name" >&2
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
    printf 'FAIL  %s region: the enforcer path changed after startup (self=%s, bound at startup=%s)\n' \
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
# (c), which is exactly the hole this closes. A `got=$want` comparison fails (b),
# and rejecting everything fails (c). Round 13 (R12-3): a completed probe is
# recorded in the ledger above, which `enforce_substance` asserts.
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
  if [ -z "${self:-}" ]; then
    printf 'FAIL  cannot locate %s to check the substance pins\n' "$0" >&2
    return 1
  fi
  # F2 (adversarial round 5): every guarded read below uses `${var:-}` so that a
  # deleted definition reaches an explicit FAIL instead of expanding unbound.
  # Under `set -u` an unbound expansion *inside the EXIT trap* prints its error,
  # leaves bash exiting 0 and silently skips the gate (measured: delete
  # `PINNED_REGION_COUNT` → rc 0, CI green). The trap call is also wrapped in a
  # subshell so any future fatal error becomes a nonzero rc rather than exit 0.
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
  canary_right=${SCEN6_REGION_SHA:-}
  canary_wrong=$(flip_hex "$canary_right")
  PIN_FAILS=0
  REGION_HASHED=0
  REGION_HASHED_RECORD=''
  run_pin_checks "scenario-6 SCEN6_REGION_SHA ${canary_wrong}" 2>/dev/null
  canary_hashed=$REGION_HASHED
  canary_fails=$PIN_FAILS
  PIN_FAILS=0
  REGION_HASHED=0
  REGION_HASHED_RECORD=''
  run_pin_checks "scenario-6 SCEN6_REGION_SHA ${canary_right}" 2>/dev/null
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
  if region_pin_check scenario-6 SCEN6_REGION_SHA "$canary_wrong" 2>/dev/null; then
    printf 'FAIL  enforcer canary: the region comparison accepted an injected wrong pin; it is neutered\n' >&2
    return 1
  fi
  if [ "$REGION_HASHED" -ne 1 ]; then
    printf 'FAIL  enforcer canary: the rejected wrong pin was not hashed (hasher ran %s time(s), expected 1)\n' \
      "$REGION_HASHED" >&2
    return 1
  fi
  REGION_HASHED=0
  if ! region_pin_check scenario-6 SCEN6_REGION_SHA "$canary_right" 2>/dev/null; then
    printf 'FAIL  enforcer canary: the region comparison rejected a correct pin; it rejects everything\n' >&2
    return 1
  fi
  if [ "$REGION_HASHED" -ne 1 ]; then
    printf 'FAIL  enforcer canary: the accepted correct pin was not hashed (hasher ran %s time(s), expected 1)\n' \
      "$REGION_HASHED" >&2
    return 1
  fi
  # The hashing read must follow the path it is given: a `region_lines` redirected
  # to a frozen pristine copy would hash that copy and leave every pin inert while
  # the report stayed honest (round 9, R9-2). A path that cannot exist must hash to
  # the digest of empty input; a redirected read returns the copy's digest.
  REGION_HASHED=0
  region_sha scenario-6 "$CANARY_MISSING_PATH" 2>/dev/null
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
  # `$tmp` is already removed by `cleanup_all` before the enforcers run, so the
  # probe builds its own directory under the system temp dir.
  mutation_dir=$(mktemp -d "${TMPDIR:-/tmp}/enforcer-mutation.XXXXXX") || mutation_dir=''
  if [ -z "$mutation_dir" ]; then
    printf 'FAIL  enforcer canary: cannot create the content-mutation probe directory\n' >&2
    return 1
  fi
  MUTATION_PROBES=0
  MUTATION_PROBE_RECORD=''
  if ! mutation_probe scenario-6 SCEN6_REGION_SHA "${SCEN6_REGION_SHA:-}" "$mutation_dir" ||
    ! mutation_probe scenario-7 SCEN7_REGION_SHA "${SCEN7_REGION_SHA:-}" "$mutation_dir"; then
    rm -rf "$mutation_dir"
    return 1
  fi
  # The probe's own ledger: both regions must have completed a probe. Round 14
  # (F3) records each copy's real digest instead of a bare name, and the loop
  # below re-hashes the copies on disk and re-runs the comparison against each in
  # both directions — so moving the ledger write to the top of `mutation_probe`
  # and returning 0 reds here instead of staying green (measured). The file pin
  # in ci.yml is the outer defence, not the only one (round 13, R12-3).
  mutated_record=''
  mutated_fail=0
  # shellcheck disable=SC2086  # intentional word split: PINNED_REGIONS is a name list
  for name in ${PINNED_REGIONS:-}; do
    case $name in
      scenario-6) const=SCEN6_REGION_SHA; want=${SCEN6_REGION_SHA:-} ;;
      scenario-7) const=SCEN7_REGION_SHA; want=${SCEN7_REGION_SHA:-} ;;
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
  if [ "$MUTATION_PROBES" -ne 2 ] || [ "$MUTATION_PROBE_RECORD" != "$mutated_record" ] || [ "$mutated_fail" -ne 0 ]; then
    printf 'FAIL  enforcer canary: the content-mutation probe recorded [%s] (%s completed) and the copies this caller independently re-hashed imply [%s]; the probe did not run against both pinned regions, its ledger was written without hashing the copies, or the pin comparison did not reject the mutated copies and accept their real digests\n' \
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
      scenario-6) const=SCEN6_REGION_SHA; want=${SCEN6_REGION_SHA:-} ;;
      scenario-7) const=SCEN7_REGION_SHA; want=${SCEN7_REGION_SHA:-} ;;
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
  # guarded file: `trap - EXIT`, `elif false` or a shortened list all leave the
  # line absent and the step red. Nothing else prints it. The count it names is
  # the hasher's own ledger (round 12), not a caller's tally.
  printf 'pinned regions verified %s/%s: %s\n' \
    "$REGION_HASHED" "$PINNED_REGION_COUNT" "$PINNED_REGIONS"
  return 0
}

cleanup_all() {
  local rc=$? min_raw
  [ -z "$tmp" ] || rm -rf "$tmp"
  if [ "$rc" -eq 0 ]; then
    # Fail closed: `[ NaN -lt 1 ]` is status 2, and `if`/`elif` read status 2 as
    # false, so an unparseable floor used to skip every branch below and exit 0
    # (measured: delete a scenario's assertions, set MIN_CHECKS=NaN, rc 0). The
    # case arms reject a floor that is not a number, and the digits-only arm also
    # rejects a zero-padded zero; the comparison under it is a string order
    # (see below), so an all-digit floor *too large* to be an integer is a
    # below-floor failure, not a status-2 skip.
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
        # silently off (R2-2, measured `RESULT: 32` rc 0 with the floor written
        # `000`). Strip the leading zeros — a plain string strip, not
        # `$(( … ))`, whose base detection is the thing being avoided — and treat
        # the result as the floor; `min_raw` keeps the author's spelling for the
        # diagnostic. Only zeros leave an empty string, i.e. the disabled case.
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
              # Ordered comparison of *digit strings* — length first, then
              # left-to-right at equal length — never a bare `[ … -lt … ]`. An
              # all-digit floor above the signed 64-bit range is unparseable as
              # an integer but fine as a string: `[ "$checks" -lt "$MIN_CHECKS" ]`
              # on `9223372036854775808` returns status 2 (stderr
              # `[: 9223372036854775808: integer expression expected`), `if`
              # reads status 2 as false, the below-floor branch is skipped and a
              # gutted run still exits 0
              # (R3-1; measured rc 0). The digits-only arm above cannot catch it
              # — the value *is* all digits. After the leading-zero strip above,
              # length-then-string order is exactly numeric order for digit
              # strings and cannot return status 2 for any value.
              if [ "${#checks}" -lt "${#MIN_CHECKS}" ] ||
                { [ "${#checks}" -eq "${#MIN_CHECKS}" ] && [ "$checks" \< "$MIN_CHECKS" ]; }; then
                printf 'FAIL  suite exited 0 after only %s check(s); expected at least %s — scenarios did not run\n' \
                  "$checks" "$MIN_CHECKS" >&2
                rc=1
              # F2 (adversarial round 5): the enforcer runs in a subshell so that
              # a `set -u` fatal inside it (an unbound expansion in the trap)
              # yields a nonzero rc here instead of bash exiting 0 with the gate
              # skipped.
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

self=${BASH_SOURCE[0]:-$0}
case "$self" in
  */*) ;;
  *) if [ -e "$self" ]; then
       self=$PWD/$self
     else
       self=$(command -v -- "$self") || {
         printf 'FAIL  cannot locate the harness: %s\n' "$0"; exit 1; }
     fi ;;
esac
# Follow symlinks to the real file before deriving the repo root. Without this,
# invoking the harness through a symlink (a `ln -s … /tmp/rhfx.sh`, or a wrapper
# in another directory) resolved `../..` against the *link's* directory and looked
# for `//scripts/repo-health.sh`. `readlink -f` is not POSIX and older macOS/BSD
# releases lack it, so loop on plain `readlink`, resolving each target against the
# link's own directory. Bounded for defence in depth, but the bound is
# unreachable in practice: `bash` cannot open this file through a cycle at all —
# the kernel refuses the chain first (measured on this host with a physical path:
# a 32-link chain to this file runs green, a 33-link chain is refused with `Too
# many levels of symbolic links`, rc 126; Linux allows 40 hops, Darwin 32, so the
# kernel always fires before the counter passes 40). An earlier probe under
# `/tmp` counted one hop fewer because `/tmp` is itself a symlink on this host,
# and the prefix's symlinks count toward the same kernel limit; the number in
# `02723f36`'s message is that earlier count. Scenario 8 pins the refusal.
n=0
while [ -L "$self" ]; do
  dir=$(cd -P -- "$(dirname -- "$self")" && pwd) || exit 1
  link=$(readlink -- "$self") || exit 1
  case "$link" in
    /*) self=$link ;;
    *)  self=$dir/$link ;;
  esac
  n=$((n + 1))
  if [ "$n" -gt 40 ]; then
    # Defensive only: unreachable while the kernel's own limit is <= 40 hops
    # (see the comment above and scenario 8). Kept so a platform that does
    # resolve deeper still fails loudly here instead of looping.
    printf 'FAIL  cannot resolve the harness path (symlink cycle?): %s\n' "$0"
    exit 1
  fi
done
# Make `$self` absolute before scenario 8 links to it: it can still be the
# relative path the caller typed (`scripts/tests/repo-health-fixtures.sh`), which
# only resolves from the repo root — a link created under `$tmp` would dangle.
self=$(cd -P -- "$(dirname -- "$self")" && pwd)/$(basename -- "$self")
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
cd -P -- "$(dirname -- "$self")/../.." || exit 1
RH=$PWD/scripts/repo-health.sh
if [ ! -f "$RH" ]; then
  printf 'FAIL  cannot find the script under test: %s\n' "$RH"
  exit 1
fi
RC_PY=$PWD/scripts/rust_comments.py
if [ ! -f "$RC_PY" ]; then
  printf 'FAIL  cannot find the module the script under test imports: %s\n' "$RC_PY"
  exit 1
fi

tmp=$(mktemp -d) || exit 1

printf '%s\n' 'repo-health.sh fixture checks'

# new_tree <name> — print the path of a throwaway root carrying the script under
# test at scripts/repo-health.sh and an empty docs/archive/.
new_tree() {
  d=$tmp/$1
  mkdir -p "$d/scripts" "$d/docs/archive" "$d/.github/workflows" || return 1
  cp "$RH" "$d/scripts/repo-health.sh" || return 1
  printf '%s\n' "$d"
}

# new_full_tree <name> — new_tree plus the stub measurement inputs that let every
# `.rs` walk actually run. A bare tree cannot show that: the Unsafe usage table
# and the SAFETY scan die on `import rust_comments` (no scripts/ module), and the
# fourth walk (`unsafe_counts` in the doc-figures block) is never reached because
# the preflight reports the missing measurement inputs first and exits. The stubs
# are deliberately minimal — the doc-figure claims below them will not match, so
# the tree is red anyway; that is fine, the checks read per-walk rows.
new_full_tree() {
  d=$(new_tree "$1") || return 1
  mkdir -p "$d/frp-core/src" "$d/frp-vnet/src" "$d/frp-core/benches" \
           "$d/frp-server/benches" "$d/vendor/rustls" "$d/vendor/yamux" \
           "$d/vendor/russh" || return 1
  cp "$RC_PY" "$d/scripts/rust_comments.py" || return 1
  # `--list` must yield a non-empty token list or count_compat() reports a
  # partial tree and exits before unsafe_counts (site 4) runs.
  cat > "$d/scripts/compat-test.sh" <<'STUB' || return 1
#!/usr/bin/env bash
if [ "${1:-}" = "--list" ]; then printf 'test_alpha\ntest_beta\n'; fi
exit 0
STUB
  printf '#!/usr/bin/env bash\nexit 0\n' > "$d/scripts/protocol-matrix.sh"
  printf '[package]\nname = "frp-core"\nversion = "0.71.0"\n' > "$d/frp-core/Cargo.toml"
  for v in rustls yamux russh; do
    printf '[package]\nname = "%s"\nversion = "1.2.3"\n' "$v" > "$d/vendor/$v/Cargo.toml"
  done
  printf 'pub fn placeholder() {}\n' > "$d/frp-core/src/lib.rs"
  printf 'pub fn placeholder() {}\n' > "$d/frp-vnet/src/lib.rs"
  printf 'pub fn placeholder() {}\n' > "$d/frp-core/benches/crypto_bridge.rs"
  printf 'pub fn placeholder() {}\n' > "$d/frp-server/benches/nathole.rs"
  printf '%s\n' "$d"
}

# mut_rwalk <tree> <site> — revert, in the tree's copy of the script, the "a file
# that cannot be stat-ed is still read, so its error is reported" fall-through at
# one of the four `.rs` walk sites. Site 1 is `rs_texts`' `fresh()`; sites 2-4 are
# the three inline walks in file order (Unsafe usage table, SAFETY scan,
# unsafe_counts). The anchor count is asserted, so a refactor that moves the code
# fails the mutation loudly instead of mutating nothing — which would leave the
# teeth-checks vacuously green.
mut_rwalk() {
  python3 - "$1" "$2" <<'PY'
import sys
tree, site = sys.argv[1], int(sys.argv[2])
p = tree + '/scripts/repo-health.sh'
s = open(p).read()
if site == 1:
    old = '        except OSError:\n            return os.path.realpath(path)'
    assert s.count(old) == 1, 'site 1 anchor found %d times' % s.count(old)
    s = s.replace(old, '        except OSError:\n            return None', 1)
else:
    old = 'key = real'
    assert s.count(old) == 3, 'site 2-4 anchor found %d times' % s.count(old)
    i = -1
    for _ in range(site - 1):
        i = s.find(old, i + 1)
    s = s[:i] + 'continue' + s[i + len(old):]
open(p, 'w').write(s)
PY
}

# mut_npresent <tree> — move the site-4 `n_present` increment past the shared
# dedupe `continue`. That refactor is count-inert (blocks/fns/impls are unchanged
# — the deduped file was never going to be counted) and only changes the
# crate-root row, which is exactly what scenario 7 pins. The anchor is asserted
# so a refactor that moves the code fails loudly instead of mutating nothing.
mut_npresent() {
  python3 - "$1" <<'PY'
import sys
p = sys.argv[1] + '/scripts/repo-health.sh'
s = open(p).read()
old = ('                n_present += 1\n'
       '                if key in seen:\n'
       '                    continue\n')
new = ('                if key in seen:\n'
       '                    continue\n'
       '                n_present += 1\n')
assert s.count(old) == 1, 'n_present anchor found %d times' % s.count(old)
open(p, 'w').write(s.replace(old, new, 1))
PY
}

# mut_walkerr <tree> <b|c> — the two `unsafe_counts` walk-error mutants the
# doc-figures block's guard exists for, both invisible to every other fixture
# (each keeps rc 1 and prints no extra FAIL row):
#   b: drop `onerror=walk_error` from the `unsafe_counts` walk. It is the walk
#      that fills `walk_errors`, so the collection stays empty and the
#      `n_present == 0` raise accuses a crate the walk could not read.
#   c: drop `and not walk_errors` from that raise — the same false accusation
#      while the walk error *was* collected.
# `os.walk(src, onerror=walk_error)` occurs three times (the Unsafe usage table,
# the SAFETY scan, `unsafe_counts` in file order); the anchor count is asserted
# and the site is picked by index, so a refactor that moves the walk fails the
# mutation loudly instead of mutating the wrong block.
mut_walkerr() {
  python3 - "$1" "$2" <<'PY'
import sys
tree, shape = sys.argv[1], sys.argv[2]
p = tree + '/scripts/repo-health.sh'
s = open(p).read()
if shape == 'b':
    old = 'os.walk(src, onerror=walk_error)'
    assert s.count(old) == 3, 'walk anchor found %d times' % s.count(old)
    i = -1
    for _ in range(3):
        i = s.find(old, i + 1)
    s = s[:i] + 'os.walk(src)' + s[i + len(old):]
else:
    old = 'if n_present == 0 and not walk_errors:'
    assert s.count(old) == 1, 'walk_errors anchor found %d times' % s.count(old)
    s = s.replace(old, 'if n_present == 0:', 1)
open(p, 'w').write(s)
PY
}

# mut_prefix <tree> — drop the separator from `unsafe_counts`' containment test,
# so a sibling directory whose name merely *starts with* the crate name
# (`frp-core-fake/` next to `frp-core/`) is treated as inside the crate and its
# `.rs` files are counted in the crate's row. The anchor occurs four times
# (`rs_texts.fresh` and the three inline walks); the fourth, in file order, is
# `unsafe_counts`. The count is asserted and the site picked by index, so a
# refactor fails loudly rather than mutating another walk.
mut_prefix() {
  python3 - "$1" <<'PY'
import sys
p = sys.argv[1] + '/scripts/repo-health.sh'
s = open(p).read()
old = 'if not real.startswith(within_real + os.sep):'
assert s.count(old) == 4, 'containment anchor found %d times' % s.count(old)
i = -1
for _ in range(4):
    i = s.find(old, i + 1)
s = s[:i] + 'if not real.startswith(within_real):' + s[i + len(old):]
open(p, 'w').write(s)
PY
}

# tree <name> [full] — set TREE to a fresh throwaway root, or stop the harness
# loudly. The helpers return non-zero when a `mkdir`/`cp` fails, but a bare
# `t=$(new_tree …)` hides that status, and the scenario then ran against an empty
# tree: measured with `chmod 000 scripts/repo-health.sh`, both `newline … no forged
# hit from the split path` checks and `clean archive scan: no archive exit-3 row`
# went vacuous-green while the run was still rc 1 for unrelated reasons.
# Scenario 9 pins this failure, and `setup_die` is the only stop: the helpers
# return non-zero exactly when they printed no root, so a successful call always
# sets a non-empty `TREE`. A second `[ -z "$TREE" ]` guard used to stand here; it
# was reachable only under scenario 9's mutant (`setup_die`'s `exit 1` changed to
# `return 0`), where it fired as an extra `fixture abort:` row that scenario 9
# reads as a row running past the setup FAIL. Pinning it with a scenario was
# rejected: forcing an empty root drives every other scenario, and re-enters this
# harness's own self-copy, against the filesystem root.
tree() {
  if [ -n "${2:-}" ]; then
    TREE=$(new_full_tree "$1") || setup_die "new_full_tree $1"
  else
    TREE=$(new_tree "$1") || setup_die "new_tree $1"
  fi
}

setup_die() {
  bad "fixture setup: $1 failed (mkdir/cp rc) — every check below it would be vacuous"
  exit 1
}

# out_count <needle> — how many lines of the last run_gate output contain it.
out_count() { printf '%s\n' "$out" | grep -cF -- "$1"; }

# run_gate <tree> — run the copied script from inside the tree; sets rc and out.
run_gate() {
  out=$(cd "$1" && bash scripts/repo-health.sh 2>&1)
  rc=$?
}

# assert_exit_mapping <label> <exact FAIL row> — the process rc is 1 (never 3),
# and that specific row is printed. Measured vacuity of the looser check: a bare
# tree already prints `path-reference scan produced no result (exit 3)` and
# `doc figures not evaluated — the tree is partial (exit 3)`, so `rc=1` plus
# "some `(exit 3)` row" held with the archive gate's own `sys.exit(3)` changed
# to `sys.exit(0)` *and* with that row's annotation reworded.
assert_exit_mapping() {
  if [ "$rc" -eq 1 ]; then
    ok "$1: process rc is 1"
  else
    bad "$1: process rc is $rc (expected 1 — a bare exit 3/fail=3 regression?)"
  fi
  if printf '%s\n' "$out" | grep -qF -- "$2"; then
    ok "$1: the expected FAIL row is printed"
  else
    bad "$1: expected FAIL row missing: $2"
  fi
}

# --- scenario 1: a gate exits 3 ---------------------------------------------
# A dangling symlink under docs/archive/ makes the archive-path scan record a
# read error and exit 3; the wrapper must still return 1 and say `(exit 3)`.
hdr
printf '%s\n' 'scenario 1: a gate exits 3 (dangling docs/archive symlink)'
tree exit3
t=$TREE
ln -s nowhere.md "$t/docs/archive/bad.md"
run_gate "$t"
assert_exit_mapping 'exit-3 gate' '  FAIL  archive path scan failed (exit 3)'
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
tree newline
t=$TREE
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

# --- scenario 3: a newline in a workflow *directory* ------------------------
# The guard must test the whole path, not the basename: a directory named
# `sub<LF>C forged.yml` around a `probe.yml` carrying a floating-toolchain line
# makes the scan print a `D <path>:<line>:<text>` hit whose first line is the
# directory fragment; the `C ` rest is then re-parsed as a fabricated
# `toolchain:` input (measured: `FAIL 1 toolchain: input(s)`).
hdr
printf '%s\n' 'scenario 3: a workflow directory containing a newline'
tree newline-dir
t=$TREE
dir="$t/.github/workflows/"$'sub\nC forged.yml'
mkdir -p "$dir"
printf 'name: probe\non: push\njobs:\n  a:\n    steps:\n      - run: rustup default stable\n' > "$dir/probe.yml"
run_gate "$t"
if printf '%s\n' "$out" | grep -q 'workflow path with a newline in its name was not scanned'; then
  ok 'newline dir: the workflow is refused by name'
else
  bad 'newline dir: no refusal naming the workflow'
fi
if printf '%s\n' "$out" | grep -q 'toolchain:.*input(s)'; then
  bad 'newline dir: a forged toolchain: hit was parsed from the split line'
else
  ok 'newline dir: no forged hit from the split path'
fi
if printf '%s\n' "$out" | grep -q 'toolchain input scan not evaluated'; then
  ok 'newline dir: the scan reports itself not evaluated (fail-closed)'
else
  bad 'newline dir: the scan did not report itself not evaluated'
fi
if [ "$rc" -eq 1 ]; then
  ok 'newline dir: process rc is 1'
else
  bad "newline dir: process rc is $rc (expected 1)"
fi

# --- scenario 4: an unreadable .rs reaches every walk site ------------------
# Containment must not be checked before readability: a dangling symlink in
# `frp-core/src/` resolves *outside* the crate, and skipping it there hides the
# read error, so a source-count gate would print `ok` over an unreadable input.
# Four separate `.rs` walks exist, and a bare tree pins only the first, so the
# fixture supplies the stub inputs that let all four run and pins each site's own
# evidence: the path is reported by the three read-scope walks (site 1 walks two
# scopes, hence 4 lines) and named by the doc-figures block as a partial tree.
# The four mutants below are what give those two checks teeth — reverting the
# fall-through at any one site drops its line(s), or the partial-tree row.
hdr
printf '%s\n' "scenario 4: an unreadable .rs reaches every walk site"
tree unreadable full
t=$TREE
ln -s nowhere "$t/frp-core/src/zz_broken.rs"
run_gate "$t"
n=$(out_count 'scan error: frp-core/src/zz_broken.rs')
if [ "$n" -eq 4 ]; then
  ok 'unreadable src: reported by all three read-scope walks (4 = src + crate scope)'
else
  bad "unreadable src: expected 4 scan-error lines, got $n"
fi
if printf '%s\n' "$out" | grep -qF 'partial tree: frp-core/src/zz_broken.rs is missing'; then
  ok 'unreadable src: the doc-figures block reports it as a partial tree (site 4)'
else
  bad 'unreadable src: unsafe_counts dropped the broken path (site 4)'
fi
if [ "$rc" -eq 1 ]; then
  ok 'unreadable src: process rc is 1'
else
  bad "unreadable src: process rc is $rc (expected 1)"
fi
for site in 1 2 3 4; do
  tree "unreadable-mut$site" full
  t=$TREE
  ln -s nowhere "$t/frp-core/src/zz_broken.rs"
  # A mutation that does not apply must be a hard failure, not a silently absent
  # edit: the site check below would then pass on the un-mutated tree and report
  # "check has teeth" for the wrong reason. (set -u/-o pipefail, no -e, and the
  # python `assert` is unchecked by the caller, so test the rc here.)
  if ! mut_rwalk "$t" "$site"; then
    bad "unreadable src: site $site mutation failed to apply — anchor missing, the site check would be vacuous"
    continue
  fi
  run_gate "$t"
  if [ "$site" -eq 4 ]; then
    # Site 4 emits no `scan error:` line (it raises out of the whole block), so
    # its revert is pinned by the partial-tree row instead of the count.
    if printf '%s\n' "$out" | grep -qF 'partial tree: frp-core/src/zz_broken.rs is missing'; then
      bad "unreadable src: site $site reverted but the partial-tree row survived"
    else
      ok "unreadable src: site $site revert drops the partial-tree row (check has teeth)"
    fi
  else
    # Exact remainder, not "anything but 4": site 1 walks two scopes, so its
    # revert drops two of the four lines; sites 2/3 drop one each. Measured
    # (baseline 4): site 1 -> 2, sites 2/3 -> 3. A walk that dropped *more* than
    # its own evidence would be a real regression and must not read `ok`.
    case "$site" in 1) want=2 ;; *) want=3 ;; esac
    n=$(out_count 'scan error: frp-core/src/zz_broken.rs')
    if [ "$n" -eq "$want" ]; then
      ok "unreadable src: site $site revert leaves exactly $want of 4 scan-error lines ($n — check has teeth)"
    else
      bad "unreadable src: site $site revert left $n scan-error line(s); measured baseline 4, this site's drop is 4 -> $want"
    fi
  fi
done

# --- scenario 5: the archive (exit 3) row is not printed unconditionally ----
# Negative control for scenario 1: a wrapper that printed the `(exit 3)` row
# without the gate having exited 3 would satisfy scenario 1 while the report no
# longer reflects the gate at all.
hdr
printf '%s\n' 'scenario 5: the archive exit-3 row is absent when the scan succeeds'
tree clean-archive
t=$TREE
run_gate "$t"
if printf '%s\n' "$out" | grep -qF '  FAIL  archive path scan failed'; then
  bad 'clean archive scan: the archive exit-3 row was printed anyway'
else
  ok 'clean archive scan: no archive exit-3 row'
fi

# --- scenario 6: the integration-test-dir metric, with its heuristic ---------
# The metric counts `tests/` directories that carry at least one `.rs` file
# beneath them (a `.rs` anywhere below counts, however deep; a `tests/` dir with
# no `.rs` is dropped). Asserted, not described: a `scripts/tests/` holding a
# non-Rust file must not count, so this pins the F4 fix that stopped the harness'
# own script directory from inflating the number, and both the nested-file rule
# and the "has a .rs" rule at once.
#
# The verdict is a `substance pin` region: the count floor can only see how many
# assertions ran, so replacing this check's condition with `if true; then` kept
# the total (32), every label, and CI green (RH-M2, measured by the adversarial
# reviewer). `enforce_substance` checksums the region instead.
# --- substance pin: scenario-6 (checksummed by enforce_substance) ---
hdr
printf '%s\n' 'scenario 6: the integration-test-dir metric counts only .rs-bearing tests/'
tree testdirs
t=$TREE
mkdir -p "$t/scripts/tests" "$t/frp-core/tests" "$t/frp-vnet/tests/deep"
printf '#!/bin/sh\n:\n' > "$t/scripts/tests/not-rust.sh"
printf 'fn t() {}\n' > "$t/frp-core/tests/it.rs"
printf 'fn u() {}\n' > "$t/frp-vnet/tests/deep/nested.rs"
run_gate "$t"
if printf '%s\n' "$out" | grep -qF 'integration test dirs: 2'; then
  ok 'integration test dirs: 2 (scripts/tests dropped; nested .rs counted)'
else
  bad "integration test dirs: expected 2, got $(printf '%s\n' "$out" | grep -F 'integration test dirs' || echo none)"
fi
# --- end substance pin: scenario-6 ---

# --- scenario 7: site 4 counts an aliased crate root as present --------------
# `unsafe_counts` increments `n_present` *before* the shared-inode dedupe
# `continue`, deliberately: "this root carries a .rs file" must not become false
# because the first crate claimed the inode. A hard link from one crate's `src`
# into another crate's tree is exactly that case — the alias resolves inside its
# own crate (so containment passes), yet its inode was already claimed — and with
# the increment moved after the `continue` the crate would raise the misleading
# `has no .rs files` partial-tree row. An intra-crate alias cannot pin this (the
# count would change too), and a `new_full_tree` without the aliased root always
# has its own placeholder. The mutation is count-inert, so only this row moves.
# --- substance pin: scenario-7 (checksummed by enforce_substance) ---
hdr
printf '%s\n' 'scenario 7: a crate root holding only a cross-crate alias is not "no .rs files"'
tree aliased full
t=$TREE
rm -f "$t/frp-vnet/src/lib.rs"
ln "$t/frp-core/src/lib.rs" "$t/frp-vnet/src/alias.rs" || bad 'aliased root: cannot hard-link the alias'
run_gate "$t"
if printf '%s\n' "$out" | grep -qF 'frp-vnet/src has no .rs files'; then
  bad 'aliased root: the crate-root row fired although the directory holds a .rs alias'
else
  ok 'aliased root: the crate-root row is suppressed (the increment precedes the dedupe continue)'
fi
if mut_npresent "$t"; then
  run_gate "$t"
  if printf '%s\n' "$out" | grep -qF 'frp-vnet/src has no .rs files'; then
    ok 'aliased root: moving the increment past the dedupe re-raises the row (check has teeth)'
  else
    bad 'aliased root: the increment-after-dedupe mutation did not re-raise the row'
  fi
else
  bad 'aliased root: mut_npresent failed to apply — anchor missing, the check would be vacuous'
fi
# --- end substance pin: scenario-7 ---

# --- scenario 8: the readlink bound is defensive; the kernel fires first -----
# The harness resolves its own symlink chain (so a wrapper or `ln -s` invocation
# still finds the repo root) and bounds the loop at 40 hops "so a symlink cycle
# cannot hang the run". That branch cannot be reached: `bash` cannot open the file
# through a cycle, because the kernel refuses the chain first (measured on this
# host with a physical path: a 32-link chain to this file runs green, a 33-link
# chain is refused — the earlier "31/32" came from probing under `/tmp`, itself a
# symlink; Linux allows 40 hops, Darwin 32, so 41 hops below is refused on both).
# The assertable half is that refusal — loud, immediate, and not a hang.
hdr
printf '%s\n' 'scenario 8: a 41-link symlink chain is refused by the kernel, not by the bound'
chain=$tmp/chain
mkdir -p "$chain" || bad 'symlink chain: cannot create its directory'
chain_ok=1
prev=$self
entry=
i=0
while [ "$i" -le 40 ]; do
  if ! ln -s "$prev" "$chain/l$i"; then chain_ok=0; break; fi
  prev=$chain/l$i
  entry=$chain/l$i
  i=$((i + 1))
done
if [ "$chain_ok" -ne 1 ]; then
  bad 'symlink chain: could not build the 41-link chain'
else
  # Enter at the **tail** of the chain: `l0` points straight at this harness, so
  # running it would re-run the whole suite instead of traversing 41 links.
  out=$(bash "$entry" 2>&1); rc=$?
  if [ "$rc" -eq 126 ] && printf '%s\n' "$out" | grep -qF 'Too many levels of symbolic links'; then
    ok 'symlink chain: 41 hops is refused by the kernel (rc 126, ELOOP) — the in-script bound is unreachable'
  else
    bad "symlink chain: expected the kernel refusal (rc 126 + ELOOP), got rc=$rc, first line: $(printf '%s' "$out" | head -1)"
  fi
fi

# --- scenario 9: a failed fixture setup stops the run ------------------------
# `new_tree`/`new_full_tree` used to ignore their `mkdir`/`cp` rc: with the script
# under test unreadable (`chmod 000`) the copy silently did not happen and three
# checks went vacuous-green — both `newline … no forged hit from the split path`
# checks and `clean archive scan: no archive exit-3 row` — while the run was still
# rc 1 for unrelated reasons. `tree` now stops at the failed setup. The fixture is
# a *copy* of this harness (at `<root>/scripts/tests/`), so the repo's own script
# is never chmod-ed and the copy fails its first `cp` for the same reason. The
# *abort* is the point, not the message: with `setup_die`'s `exit 1` mutated to
# `return 0` the outer harness stayed at rc 0 / `RESULT: … hold` while the inner
# run printed six vacuous `ok` rows past the FAIL — including scenarios 7 and 8's
# own rows — and went on to attempt `mkdir -p /scripts/… /docs/archive
# /.github/workflows`. The last check below pins that nothing follows the FAIL.
hdr
printf '%s\n' 'scenario 9: an unreadable script under test fails the run loudly'
t=$tmp/selfcheck
mkdir -p "$t/scripts/tests" "$t/docs/archive" "$t/.github/workflows" || bad 'setup-failure fixture: cannot create its root'
cp "$self" "$t/scripts/tests/harness.sh" || bad 'setup-failure fixture: cannot copy this harness'
cp "$RH" "$t/scripts/repo-health.sh" || bad 'setup-failure fixture: cannot copy the script under test'
cp "$RC_PY" "$t/scripts/rust_comments.py" || bad 'setup-failure fixture: cannot copy rust_comments.py'
chmod 000 "$t/scripts/repo-health.sh"
out=$(cd "$t/scripts/tests" && bash harness.sh 2>&1); rc=$?
if [ "$rc" -eq 1 ]; then
  ok 'unreadable script under test: the copied harness exits 1'
else
  bad "unreadable script under test: expected rc 1, got $rc"
fi
if printf '%s\n' "$out" | grep -qF 'fixture setup: new_tree'; then
  ok 'unreadable script under test: the failure names the setup step'
else
  bad "unreadable script under test: no setup FAIL row — the checks below it would go vacuous-green: $(printf '%s' "$out" | head -3)"
fi
past=$(printf '%s\n' "$out" | awk '
  !seen && /^  FAIL  fixture setup: / { seen = 1; next }
  seen && $0 !~ /^[[:space:]]*$/ { print }
')
if [ -z "$past" ]; then
  ok 'unreadable script under test: nothing runs past the failed setup (the FAIL is the last row)'
else
  bad "unreadable script under test: rows ran past the failed setup: $(printf '%s' "$past" | head -3 | tr '\n' '|')"
fi

# unreadable_dir_tree <name> — a full tree whose `frp-vnet/src` holds an
# unreadable subdirectory and no readable `.rs` of its own (frp-core/src keeps its
# placeholder, so the tree still holds a readable `.rs` elsewhere). Both
# `unsafe_counts` walk-error mutants turn this shape into the false
# `frp-vnet/src has no .rs files` row.
unreadable_dir_tree() {
  tree "$1" full
  rm -f "$TREE/frp-vnet/src/lib.rs"
  mkdir -p "$TREE/frp-vnet/src/hidden" || setup_die "unreadable_dir_tree $1"
  chmod 000 "$TREE/frp-vnet/src/hidden"
}

# --- scenario 10: a walk error is reported, not turned into "no .rs files" ----
# The doc-figures walk is the only thing that fills `walk_errors`, and it is what
# separates "this crate holds no `.rs` under `src/`" from "the walk could not read
# part of it". Two `scripts/repo-health.sh` mutants are invisible to every other
# fixture (each leaves rc 1 and prints no extra FAIL): dropping
# `onerror=walk_error` from the `unsafe_counts` walk, and dropping
# `and not walk_errors` from the raise below it. Both turn a crate that *has* a
# readable `.rs` (or merely an unreadable subdirectory) into the accusation
# `frp-vnet/src has no .rs files — cannot measure the doc figures`.
hdr
printf '%s\n' 'scenario 10: an unreadable directory is a walk error, not "no .rs files"'
unreadable_dir_tree walkerr
t=$TREE
run_gate "$t"
chmod 700 "$t/frp-vnet/src/hidden"
if printf '%s\n' "$out" | grep -qF 'has no .rs files'; then
  bad 'walk error: the crate is accused of holding no .rs files although the walk reported an unreadable directory'
else
  ok 'walk error: no "no .rs files" accusation while the crate walk reported an error'
fi
if printf '%s\n' "$out" | grep -qF 'walk error: '; then
  ok 'walk error: the unreadable directory is named in a walk error row'
else
  bad 'walk error: no "walk error:" row for the unreadable directory'
fi
if printf '%s\n' "$out" | grep -qF 'doc figures not evaluated — the walk reported errors (exit 2)'; then
  ok 'walk error: the doc-figures row reports the walk error (exit 2)'
else
  bad 'walk error: the doc-figures row does not report the walk error'
fi
for shape in b c; do
  unreadable_dir_tree "walkerr-$shape"
  t=$TREE
  if mut_walkerr "$t" "$shape"; then
    run_gate "$t"
    chmod 700 "$t/frp-vnet/src/hidden"
    if printf '%s\n' "$out" | grep -qF 'has no .rs files'; then
      ok "walk error ($shape): the guard mutant re-raises the false accusation (check has teeth)"
    else
      bad "walk error ($shape): the mutant did not re-raise the accusation — the check would be vacuous"
    fi
  else
    bad "walk error ($shape): mut_walkerr failed to apply — anchor missing, the check would be vacuous"
  fi
done

# --- scenario 11: containment needs the path separator ------------------------
# `unsafe_counts` excludes a file whose realpath is outside the crate root, so a
# symlink pointing into a *sibling* directory is not counted for the crate. The
# test is `real.startswith(within_real + os.sep)`: dropping the separator makes a
# sibling named `frp-core-fake/` count as inside `frp-core/` (a pure prefix
# match). The fixture places `frp-core-fake/leak.rs` (one `unsafe` block) next to
# `frp-core/` and symlinks it into `frp-core/src/`, so the mutation is visible in
# `unsafe_counts`' result — measured as the doc-figure row that reports what the
# tree measures for `frp-core`'s unsafe-block claim (the fixture's CLAUDE.md does
# not carry that claim, so the row always reports the measurement: `measures 0`
# intact, `measures 1` mutated).
#
# `unsafe_counts` is the walk the mutation targets; the *Unsafe usage table* is a
# second, separate walk in the script with its own copy of this test, so it stays
# 0 under this mutation and is deliberately not the observable here.
hdr
printf '%s\n' 'scenario 11: a sibling whose name starts with the crate name is not the crate'
tree prefix full
t=$TREE
mkdir -p "$t/frp-core-fake" || bad 'containment: cannot create the sibling directory'
printf '%s\n' '// SAFETY: fixture only.' 'pub fn placeholder() {' '    unsafe {}' '}' > "$t/frp-core-fake/leak.rs"
ln -s "$t/frp-core-fake/leak.rs" "$t/frp-core/src/leak.rs" || bad 'containment: cannot symlink the sibling file into frp-core/src'
measured_unsafe() {
  printf '%s\n' "$out" | awk '
    index($0, "frp-core: ([0-9]+) blocks") > 0 {
      for (i = 1; i <= NF; i++)
        if ($i == "measures") { print $(i + 1); exit }
    }
  '
}
run_gate "$t"
blocks=$(measured_unsafe)
if [ -z "$blocks" ]; then
  bad 'containment: no doc-figure row reports the measured frp-core unsafe-block count (the fixture must drive the doc-figures gate)'
elif [ "$blocks" = "0" ]; then
  ok 'containment: the out-of-crate alias is not counted in the doc-figure measurement for frp-core'
else
  bad "containment: the doc-figure measurement for frp-core is $blocks, expected 0 — a sibling directory leaked into it"
fi
if mut_prefix "$t"; then
  run_gate "$t"
  blocks=$(measured_unsafe)
  if [ "$blocks" = "1" ]; then
    ok 'containment: dropping the separator counts the sibling in the measurement (check has teeth)'
  else
    bad "containment: the within_real-without-separator mutation left the measurement at ${blocks:-absent}, expected 1"
  fi
else
  bad 'containment: mut_prefix failed to apply — anchor missing, the check would be vacuous'
fi

# ---------------------------------------------------------------- summary
hdr
if [ "$fail" -eq 0 ]; then
  printf 'RESULT: %d fixture check(s) hold\n' "$checks"
else
  printf 'RESULT: %d fixture check(s), failures above\n' "$checks"
fi
exit "$fail"
