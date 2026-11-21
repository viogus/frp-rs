#!/usr/bin/env bash
# protocol-matrix-floors.sh — fixture checks for `apply_floors` in
# scripts/protocol-matrix.sh and for the CI wiring that turns it on.
#
# Why this exists: the throughput-floor gate is the only thing between a
# transport that still moves bytes at a third of its speed and a green CI run
# (KCP sat at 22.25 MiB/s, a ratio of 0.042, for its whole life because
# `mbps > 0` cannot see it). Nothing exercised the checker's verdicts.
#
#   * `apply_floors` decides its verdicts from a python block inside
#     scripts/protocol-matrix.sh. `scripts/tests/compat-port-ownership.sh` greps
#     three fixed strings from that file, so a renamed emitter token (`BELOW|`)
#     or a changed exit path breaks the gate without breaking a test: the loop
#     that reads the checker's output would print nothing and, before the
#     `checked|` terminator existed, that read exactly like "every floor
#     passed".
#   * deleting `--floors scripts/protocol-matrix.floors` from
#     .github/workflows/compat.yml turns the whole gate off, and no other check
#     reads that file for the string — the matrix would keep running and keep
#     passing.
#
# This suite drives `apply_floors` through every verdict it can reach
# (below-floor, ratio, unknown row, unfloored row, unmeasured row, unparseable
# floor and rate, missing and undecodable floors file, report-only mode, and
# two distinct ways of producing no verdict at all), then reads the two files
# for the wiring no runtime check can see.
#
# Scenarios
#   A  verdicts: a clean run reports `ok` and the `checked|N|M` summary and
#      fails nothing; a below-floor row fails the run with the floor named.
#   B  ratio floors: `ratio:F` is measured against `tcp-plain`, a missing base
#      is an error rather than a silent pass, and the ratio does what it says.
#   C  floor/row mismatches: a floor naming a row the matrix never runs is an
#      error (it would otherwise gate nothing forever), a matrix row with no
#      floor is an error (it is gated only by `mbps > 0`), and a row that is in
#      the matrix but was never measured is a NOTE — it already failed its own
#      traffic check and must not be counted twice.
#   D  malformed input: an unparseable floor line, an unparseable rate entry and
#      a missing floors file each fail with their own message.
#   E  no verdict at all: an undecodable (non-UTF-8) floors file and a floors
#      file whose every row went unmeasured both end in "produced no verdict for
#      any row" — the checker crashing must never read as a pass.
#   F  report-only: `enforce=no` downgrades a below-floor row to a WARN and
#      leaves the run's failure count alone.
#   G  wiring: .github/workflows/compat.yml passes `--floors
#      scripts/protocol-matrix.floors`, and scripts/protocol-matrix.sh still
#      emits the tokens the reader loop depends on.
#
# Every case runs in-process against the sourced script: no build, no network,
# no frps.

set -u

# Pinned total, as in the sibling suites: `exit "$fails"` alone is happy with
# `RESULT: 0 fixture check(s) hold`, so a suite that silently stops checking
# must not exit green.
MIN_CHECKS=25

# The ordered assertion anchors, one per ok/bad call in scenario order. A
# scenario that stops running, a deleted check or a reordered check moves
# LABELS away from this list.
SHAPE=(
  "A clean run fails nothing"
  "A clean run reports the checked/below summary"
  "A below-floor row fails the run"
  "A below-floor row names its floor"
  "A below-floor row counts as below"
  "B a ratio floor compares against tcp-plain"
  "B a ratio floor below its threshold fails"
  "B a ratio floor with no tcp-plain base is an error"
  "C a floor naming an unknown row is an error"
  "C a matrix row with no floor is an error"
  "C an unmeasured matrix row is a NOTE, not a failure"
  "D an unparseable floor line is an error"
  "D an unparseable rate entry is an error"
  "D a missing floors file is an error"
  "D an unrecognised status line fails the run"
  "E an undecodable floors file yields no verdict"
  "E all rows unmeasured yields no verdict"
  "F report-only downgrades a below-floor row"
  "F report-only leaves the failure count alone"
  "F report-only says so in the summary line"
  "G compat.yml passes --floors scripts/protocol-matrix.floors"
  "G a commented-out --floors does not count as wired"
  "G the matrix still emits the BELOW token"
  "G the matrix still emits the checked terminator"
  "G the matrix sources only when executed"
)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/frp-floors-fixture.XXXXXX") || {
  printf 'FAIL  cannot create a scratch dir\n' >&2
  exit 1
}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
MATRIX="$ROOT/scripts/protocol-matrix.sh"
COMPAT_WF="$ROOT/.github/workflows/compat.yml"

checks=0
fails=0
LABELS=()

hdr() { printf '\n%s\n' "$1"; }
ok()  { checks=$((checks + 1)); LABELS+=("$1"); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); LABELS+=("$1"); printf '  FAIL  %s\n' "$1"; }

# shellcheck disable=SC2071
below_floor() {
  [ "${#checks}" -lt "${#MIN_CHECKS}" ] ||
    { [ "${#checks}" -eq "${#MIN_CHECKS}" ] && [[ "$checks" < "$MIN_CHECKS" ]]; }
}

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

cleanup_all() {
  local rc=$? i
  [ -z "$WORK" ] || rm -rf "$WORK"
  if [ "$rc" -eq 0 ] && [ "$fails" -gt 0 ]; then
    rc=1
  fi
  if [ "$rc" -eq 0 ]; then
    case ${MIN_CHECKS:-} in
      ''|0)
        printf 'FAIL  the check floor is disabled (MIN_CHECKS=%s)\n' "${MIN_CHECKS:-<unset>}" >&2
        rc=1 ;;
      *[!0-9]*)
        printf 'FAIL  the check floor is not a number (MIN_CHECKS=%s)\n' "$MIN_CHECKS" >&2
        rc=1 ;;
      *)
        if below_floor; then
          printf 'FAIL  suite exited 0 after only %s check(s); expected at least %s\n' \
            "$checks" "$MIN_CHECKS" >&2
          rc=1
        elif ! ( enforce_shape ); then
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

[ -f "$MATRIX" ] || { printf 'FAIL  matrix script not found: %s\n' "$MATRIX"; exit 1; }
# shellcheck source=scripts/protocol-matrix.sh
source "$MATRIX"
# `apply_floors` reports the per-row verdicts through `vlog`, which is silent
# unless `--verbose` was given. This suite is the only reader of those lines, so
# it turns them on: an assertion on "the row was skipped" is worth nothing if
# the line it matches is never printed.
VERBOSE=true

# --- helpers -----------------------------------------------------------------

FLOORS="" OUT="" BEFORE=""

# reset_state <rows...> — the sourced script's run state, set per case so a case
# cannot inherit another's failure count.
reset_state() {
  FAIL=0
  FAILURES=()
  PASS=0
  RATES=()
  ALL_ROWS=("$@")
}

floor_file() {  # floor_file <name> <content...>
  local name="$1"
  shift
  printf '%s\n' "$@" >"$WORK/$name"
  printf '%s' "$WORK/$name"
}

# run_floors <floors-path> [enforce] — captures the checker's log lines and the
# run's failure count, so a case can assert on both. The function runs in this
# shell, not in a command substitution: `apply_floors` reports through the
# caller's FAIL/FAILURES globals, and a subshell would throw those away — which
# is how a first draft of this suite read every failing case as passing.
run_floors() {
  BEFORE=$FAIL
  apply_floors "$1" "${2:-yes}" >"$WORK/out" 2>&1
  OUT=$(cat "$WORK/out")
}

has() { case "$OUT" in *"$1"*) return 0 ;; *) return 1 ;; esac; }

# floors_wired <workflow> — the flag has to appear on an executable line. A
# plain `grep -F` counts a comment, and "delete the flag but leave it named in a
# comment" is exactly the edit this check exists for, so comment lines are
# dropped first and the trailing continuation is required: the matrix invocation
# continues onto the next argument, a note about it does not.
floors_wired() {
  local code
  # Not `grep -v … | grep -q …`: a pipeline into `grep -q` can report "no match"
  # on a match when the reader exits early under `pipefail`, and the repo's
  # health gate refuses the shape outright.
  code=$(grep -v '^[[:space:]]*#' "$1" 2>/dev/null) || true
  grep -Fq -- '--floors scripts/protocol-matrix.floors \' <<<"$code"
}

# --- A: verdicts -------------------------------------------------------------

hdr "A  verdicts"

reset_state tcp-plain
RATES=("tcp-plain=200.0")
FLOORS=$(floor_file clean.floors "tcp-plain=100")
run_floors "$FLOORS"
if [ "$FAIL" -eq 0 ]; then
  ok "A clean run fails nothing"
else
  bad "A clean run fails nothing"
  printf '        output: %s\n' "$OUT"
fi
if has "floors: 1 checked, 0 below (enforced)"; then
  ok "A clean run reports the checked/below summary"
else
  bad "A clean run reports the checked/below summary"
  printf '        output: %s\n' "$OUT"
fi

reset_state tcp-plain
RATES=("tcp-plain=50.0")
FLOORS=$(floor_file below.floors "tcp-plain=100")
run_floors "$FLOORS"
if [ "$FAIL" -gt "$BEFORE" ]; then
  ok "A below-floor row fails the run"
else
  bad "A below-floor row fails the run"
  printf '        output: %s\n' "$OUT"
fi
if has "FAIL tcp-plain: throughput below floor — 50.0 MiB/s (floor 100.0 absolute)"; then
  ok "A below-floor row names its floor"
else
  bad "A below-floor row names its floor"
  printf '        output: %s\n' "$OUT"
fi
if has "floors: 1 checked, 1 below (enforced)"; then
  ok "A below-floor row counts as below"
else
  bad "A below-floor row counts as below"
  printf '        output: %s\n' "$OUT"
fi

# --- B: ratio floors ---------------------------------------------------------

hdr "B  ratio floors"

reset_state tcp-plain kcp-plain
RATES=("tcp-plain=200.0" "kcp-plain=150.0")
FLOORS=$(floor_file ratio-ok.floors "tcp-plain=100" "kcp-plain=ratio:0.5")
run_floors "$FLOORS"
if [ "$FAIL" -eq 0 ] && has "floor ok kcp-plain: 150.0 MiB/s (floor 0.5x tcp-plain = 100.0)"; then
  ok "B a ratio floor compares against tcp-plain"
else
  bad "B a ratio floor compares against tcp-plain"
  printf '        output: %s\n' "$OUT"
fi

reset_state tcp-plain kcp-plain
RATES=("tcp-plain=200.0" "kcp-plain=90.0")
FLOORS=$(floor_file ratio-below.floors "tcp-plain=100" "kcp-plain=ratio:0.5")
run_floors "$FLOORS"
if [ "$FAIL" -gt "$BEFORE" ] && has "FAIL kcp-plain: throughput below floor — 90.0 MiB/s (floor 0.5x tcp-plain = 100.0)"; then
  ok "B a ratio floor below its threshold fails"
else
  bad "B a ratio floor below its threshold fails"
  printf '        output: %s\n' "$OUT"
fi

reset_state kcp-plain
RATES=("kcp-plain=150.0")
FLOORS=$(floor_file ratio-nobase.floors "kcp-plain=ratio:0.5")
run_floors "$FLOORS"
if [ "$FAIL" -gt "$BEFORE" ] && has "FAIL floors: ratio floor for kcp-plain needs a positive tcp-plain rate"; then
  ok "B a ratio floor with no tcp-plain base is an error"
else
  bad "B a ratio floor with no tcp-plain base is an error"
  printf '        output: %s\n' "$OUT"
fi

# --- C: floor/row mismatches -------------------------------------------------

hdr "C  floor/row mismatches"

reset_state tcp-plain
RATES=("tcp-plain=200.0")
FLOORS=$(floor_file unknown-row.floors "tcp-plain=100" "ws-tls=20")
run_floors "$FLOORS"
if [ "$FAIL" -gt "$BEFORE" ] && has "FAIL floors: floor names row 'ws-tls', which is not a matrix row"; then
  ok "C a floor naming an unknown row is an error"
else
  bad "C a floor naming an unknown row is an error"
  printf '        output: %s\n' "$OUT"
fi

reset_state tcp-plain kcp-tls
RATES=("tcp-plain=200.0" "kcp-tls=200.0")
FLOORS=$(floor_file unfloored.floors "tcp-plain=100")
run_floors "$FLOORS"
if [ "$FAIL" -gt "$BEFORE" ] && has "FAIL kcp-tls: no throughput floor — the matrix row has no floor in unfloored.floors"; then
  ok "C a matrix row with no floor is an error"
else
  bad "C a matrix row with no floor is an error"
  printf '        output: %s\n' "$OUT"
fi

reset_state tcp-plain ws-tls
RATES=("tcp-plain=200.0")
FLOORS=$(floor_file unmeasured.floors "tcp-plain=100" "ws-tls=20")
run_floors "$FLOORS"
if [ "$FAIL" -eq 0 ] && has "floor skipped ws-tls: not measured"; then
  ok "C an unmeasured matrix row is a NOTE, not a failure"
else
  bad "C an unmeasured matrix row is a NOTE, not a failure"
  printf '        output: %s\n' "$OUT"
fi

# --- D: malformed input ------------------------------------------------------

hdr "D  malformed input"

reset_state tcp-plain
RATES=("tcp-plain=200.0")
FLOORS=$(floor_file garbage.floors "tcp-plain=100" "this line has no equals sign")
run_floors "$FLOORS"
if [ "$FAIL" -gt "$BEFORE" ] && has "FAIL floors: unparseable floor line: this line has no equals sign"; then
  ok "D an unparseable floor line is an error"
else
  bad "D an unparseable floor line is an error"
  printf '        output: %s\n' "$OUT"
fi

reset_state tcp-plain
RATES=("tcp-plain=not-a-number")
FLOORS=$(floor_file clean2.floors "tcp-plain=100")
run_floors "$FLOORS"
if [ "$FAIL" -gt "$BEFORE" ] && has "FAIL floors: unparseable rate entry from the matrix: tcp-plain=not-a-number"; then
  ok "D an unparseable rate entry is an error"
else
  bad "D an unparseable rate entry is an error"
  printf '        output: %s\n' "$OUT"
fi

reset_state tcp-plain
RATES=("tcp-plain=200.0")
run_floors "$WORK/absent.floors"
if [ "$FAIL" -gt "$BEFORE" ] && has "FAIL floors: file not found: $WORK/absent.floors"; then
  ok "D a missing floors file is an error"
else
  bad "D a missing floors file is an error"
  printf '        output: %s\n' "$OUT"
fi

# A verdict line the reader does not recognise is the shape a renamed or
# misspelled status takes. The reader's default arm is what turns it into a
# failure, so a stub `python3` prints one and the arm is what has to bite.
mkdir -p "$WORK/fakebin"
cat >"$WORK/fakebin/python3" <<'FAKE'
#!/usr/bin/env bash
printf 'ok|tcp-plain|100.0 MiB/s (floor 100.0 absolute)\n'
printf 'SLOW|kcp-plain|5.0 MiB/s (floor 100.0 absolute)\n'
printf 'checked|2|0\n'
FAKE
chmod +x "$WORK/fakebin/python3"

reset_state tcp-plain kcp-plain
RATES=("tcp-plain=100.0" "kcp-plain=5.0")
FLOORS=$(floor_file unknown-status.floors "tcp-plain=100" "kcp-plain=100")
REAL_PATH=$PATH
PATH="$WORK/fakebin:$PATH"
run_floors "$FLOORS"
PATH=$REAL_PATH
if [ "$FAIL" -gt "$BEFORE" ] && has "unrecognised checker output: SLOW|kcp-plain|"; then
  ok "D an unrecognised status line fails the run"
else
  bad "D an unrecognised status line fails the run"
  printf '        output: %s\n' "$OUT"
fi

# --- E: no verdict at all ----------------------------------------------------

hdr "E  no verdict at all"

# Not decodable as UTF-8: the python block raises before printing anything, so
# the reader sees an empty stream. Before the `checked|` terminator that read
# exactly like "every floor passed".
reset_state tcp-plain
RATES=("tcp-plain=200.0")
printf 'tcp-plain=100\n\xff\xfe binary junk\n' >"$WORK/undecodable.floors"
run_floors "$WORK/undecodable.floors"
if [ "$FAIL" -gt "$BEFORE" ] && has "FAIL floors: the checker produced no verdict for any row"; then
  ok "E an undecodable floors file yields no verdict"
else
  bad "E an undecodable floors file yields no verdict"
  printf '        output: %s\n' "$OUT"
fi

# A verdict stream that is only NOTEs: the checker ran, but checked nothing.
reset_state ws-tls
RATES=()
FLOORS=$(floor_file all-unmeasured.floors "ws-tls=20")
run_floors "$FLOORS"
if [ "$FAIL" -gt "$BEFORE" ] && has "FAIL floors: the checker produced no verdict for any row"; then
  ok "E all rows unmeasured yields no verdict"
else
  bad "E all rows unmeasured yields no verdict"
  printf '        output: %s\n' "$OUT"
fi

# --- F: report-only ----------------------------------------------------------

hdr "F  report-only"

reset_state tcp-plain
RATES=("tcp-plain=50.0")
FLOORS=$(floor_file below2.floors "tcp-plain=100")
run_floors "$FLOORS" no
if has "WARN tcp-plain: throughput below floor (report only) — 50.0 MiB/s (floor 100.0 absolute)"; then
  ok "F report-only downgrades a below-floor row"
else
  bad "F report-only downgrades a below-floor row"
  printf '        output: %s\n' "$OUT"
fi
if [ "$FAIL" -eq "$BEFORE" ]; then
  ok "F report-only leaves the failure count alone"
else
  bad "F report-only leaves the failure count alone"
  printf '        failures: %s -> %s\n' "$BEFORE" "$FAIL"
fi
if has "floors: 1 checked, 1 below (report only)"; then
  ok "F report-only says so in the summary line"
else
  bad "F report-only says so in the summary line"
  printf '        output: %s\n' "$OUT"
fi

# --- G: the wiring no runtime check can see ----------------------------------

hdr "G  wiring"

if [ -f "$COMPAT_WF" ] && floors_wired "$COMPAT_WF"; then
  ok "G compat.yml passes --floors scripts/protocol-matrix.floors"
else
  bad "G compat.yml passes --floors scripts/protocol-matrix.floors"
  printf '        looked in: %s\n' "$COMPAT_WF"
fi

# The regression this check exists for, in the form that defeated a plain grep:
# the flag deleted from the invocation, its name left behind in a comment.
printf '      # (was: --floors scripts/protocol-matrix.floors )\n      - run: bash scripts/protocol-matrix.sh\n' \
  >"$WORK/commented.yml"
if floors_wired "$WORK/commented.yml"; then
  bad "G a commented-out --floors does not count as wired"
  printf '        the flag was only in a comment, and the check accepted it\n'
else
  ok "G a commented-out --floors does not count as wired"
fi

if grep -Fq 'print(f"BELOW|{name}|' "$MATRIX"; then
  ok "G the matrix still emits the BELOW token"
else
  bad "G the matrix still emits the BELOW token"
  printf '        the reader loop matches BELOW; a renamed token turns the gate off silently\n'
fi

if grep -Fq 'print(f"checked|{checked}|{below}")' "$MATRIX"; then
  ok "G the matrix still emits the checked terminator"
else
  bad "G the matrix still emits the checked terminator"
  printf '        the terminator is what makes an empty verdict stream fail closed\n'
fi

if grep -Fq 'if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then' "$MATRIX"; then
  ok "G the matrix sources only when executed"
else
  bad "G the matrix sources only when executed"
  printf '        sourcing this suite would otherwise run a full matrix\n'
fi

exit 0
