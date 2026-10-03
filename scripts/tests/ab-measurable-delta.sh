#!/usr/bin/env bash
# =============================================================================
# Fixture checks for the A/B throughput gate's delta classifier and verdict
# (TODO.md:10569).
#
# Two artefacts are under test, both driven for real — no copies of their logic
# live here:
#
#   1. scripts/ab-measurable-delta.sh — the classifier. Every "does this delta
#      have anything measurable in it" case runs the real script against a
#      synthetic git repository under $WORK via AB_REPO_DIR, so the git
#      pathspec semantics (not a hand-written model of them) are what is
#      asserted. Each measured-set class gets its own fixture with a path that
#      belongs to that class and no other.
#   2. scripts/ab-matrix.sh — the gate arithmetic. `AB_MATRIX_LIB_ONLY=1`
#      sources the real gate_median / gate_verdict / gate_report definitions
#      (the source-only guard at the top of the script stops before any
#      worktree, build or server) and calls them.
#
# It also carries a MUTANT MATRIX (the sabotage converse): each mutant copies
# one of the two real scripts, applies exactly the mutation that would neuter
# one property, and re-runs THIS SUITE as a child process against the mutant.
# The suite must then go red. A green child means the fixtures do not actually
# witness the property they claim to, and the check fails. The real scripts are
# never written to; the check "real scripts are byte-identical after the mutant
# matrix" is the revert proof.
#
# Scope: no network, no VPS, no cargo, no servers — synthetic repos and pure
# functions only; the whole suite is seconds, not minutes.
#
# Exits non-zero if any check fails (or if fewer than MIN_CHECKS checks ran).
# =============================================================================
set -uo pipefail

self="${BASH_SOURCE[0]:-$0}"
case "$self" in
  /*) ;;
  *) self="$PWD/$self" ;;
esac
ROOT="$(cd -P -- "$(dirname -- "$self")/../.." && pwd)"
CLASSIFIER="${AB_MD_CLASSIFIER:-$ROOT/scripts/ab-measurable-delta.sh}"
MATRIX="${AB_MD_MATRIX:-$ROOT/scripts/ab-matrix.sh}"

# The child runs invoked by the mutant matrix run every fixture EXCEPT the
# mutant matrix itself (which would recurse forever), so they have their own
# floor. Both floors count CHECKS RUN, not checks passed: a mutant run is
# expected to fail fixtures, and the floor must not paper over an early exit.
SABOTAGE_CHILD="${AB_MD_SABOTAGE_CHILD:-0}"
if [ "$SABOTAGE_CHILD" = "1" ]; then MIN_CHECKS=37; else MIN_CHECKS=42; fi

checks=0
fails=0

ok()  { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf '  FAIL  %s\n' "$1"; }
hdr() { printf '\n%s\n' "$1"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ab-md.XXXXXX")"
cleanup_all() {
  rm -rf "$WORK"
  if [ "$checks" -lt "$MIN_CHECKS" ]; then
    bad "floor: only $checks of $MIN_CHECKS checks ran — an early exit cannot report a passing suite"
  fi
  printf '\nRESULT: %s fixture check(s) hold\n' "$((checks - fails))"
  if [ "$fails" -ne 0 ]; then
    exit 1
  fi
}
trap cleanup_all EXIT

for tool in git sed cmp tr cut grep mktemp; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FATAL: $tool not found" >&2; exit 1; }
done
python3 -c 'pass' 2>/dev/null || { echo "FATAL: python3 not found (the gate uses it)" >&2; exit 1; }

[ -f "$CLASSIFIER" ] || { echo "FATAL: classifier not found: $CLASSIFIER" >&2; exit 1; }
[ -f "$MATRIX" ]     || { echo "FATAL: gate script not found: $MATRIX" >&2; exit 1; }

hasher() {  # hasher <file> -> hex digest (portable)
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# --- synthetic repositories -------------------------------------------------
mkrepo() {  # mkrepo <dir>: an empty repo with one empty root commit
  local d="$1"
  mkdir -p "$d"
  git -C "$d" init -q
  git -C "$d" config user.email t@t
  git -C "$d" config user.name t
  git -C "$d" config commit.gpgsign false
  git -C "$d" commit -q --allow-empty -m "base"
}
sha()  { git -C "$1" rev-parse HEAD; }
commit() { git -C "$1" add -A && git -C "$1" commit -q -m "$2"; }
add_files() {  # add_files <dir> <path>...: one new revision writing each path
  local d="$1"; shift
  local p
  for p in "$@"; do
    mkdir -p "$d/$(dirname -- "$p")"
    printf 'x\n' > "$d/$p"
  done
  commit "$d" "touch: $*"
}

# classify <repo-dir> <before> <after> -> prints "rc<TAB>stdout"
classify() {
  local repo="$1" before="$2" after="$3"
  local out rc=0
  out="$(AB_REPO_DIR="$repo" bash "$CLASSIFIER" "$before" "$after" 2>/dev/null)" || rc=$?
  printf '%s\t%s' "$rc" "$out"
}

# class_fixture <label> <path>
# A repo whose only delta is <path>: the classifier must measure (rc 0) and
# print exactly that path on stdout.
class_fixture() {
  local label="$1" path="$2"
  local d="$WORK/repo-$(printf '%s' "$label" | tr -c 'a-zA-Z0-9' '-')"
  mkrepo "$d"
  local before; before="$(sha "$d")"
  add_files "$d" "$path"
  local after; after="$(sha "$d")"
  local got; got="$(classify "$d" "$before" "$after")"
  local rc="${got%%	*}" out="${got#*	}"
  if [ "$rc" = "0" ] && [ "$out" = "$path" ]; then
    ok "classifier: $label ($path) -> rc 0, path printed"
  else
    bad "classifier: $label ($path) -> expected rc 0 + '$path', got rc $rc, stdout='$out'"
  fi
}

hdr "classifier: measured-path classes (each path belongs to exactly one class)"

class_fixture "*.rs"                        "src/lib.rs"
class_fixture "root Cargo.toml"             "Cargo.toml"
class_fixture "root Cargo.lock"             "Cargo.lock"
class_fixture "nested Cargo.toml"           "crates/x/Cargo.toml"
class_fixture "nested Cargo.lock"           "crates/x/Cargo.lock"
class_fixture "rust-toolchain*"             "rust-toolchain.toml"
class_fixture ".cargo/**"                   ".cargo/config.toml"
class_fixture "scripts/frp-stress/**"       "scripts/frp-stress/main.sh"
class_fixture "scripts/ab-matrix.sh"        "scripts/ab-matrix.sh"
class_fixture "scripts/ab-remote.sh"        "scripts/ab-remote.sh"
class_fixture ".github/workflows/ab-matrix" ".github/workflows/ab-matrix.yml"
class_fixture "crates/** (non-manifest)"    "crates/x/data.json"

hdr "classifier: deltas with nothing measurable (must skip: rc 1, no stdout)"

D="$WORK/repo-records"; mkrepo "$D"; B="$(sha "$D")"
add_files "$D" CHANGELOG.md TODO.md docs/history/development-log.md
A="$(sha "$D")"
got="$(classify "$D" "$B" "$A")"; rc="${got%%	*}"; out="${got#*	}"
if [ "$rc" = "1" ] && [ -z "$out" ]; then
  ok "classifier: CHANGELOG.md + TODO.md + docs/history/development-log.md -> rc 1, no output"
else
  bad "classifier: records-only delta -> expected rc 1 and empty stdout, got rc $rc, stdout='$out'"
fi

D="$WORK/repo-prose"; mkrepo "$D"; B="$(sha "$D")"
add_files "$D" README.md docs/architecture.md
A="$(sha "$D")"
got="$(classify "$D" "$B" "$A")"; rc="${got%%	*}"; out="${got#*	}"
if [ "$rc" = "1" ] && [ -z "$out" ]; then
  ok "classifier: prose/docs paths outside the measured set -> rc 1, no output"
else
  bad "classifier: prose-only delta -> expected rc 1 and empty stdout, got rc $rc, stdout='$out'"
fi

D="$WORK/repo-empty"; mkrepo "$D"
add_files "$D" README.md
A="$(sha "$D")"
got="$(classify "$D" "$A" "$A")"; rc="${got%%	*}"; out="${got#*	}"
if [ "$rc" = "1" ] && [ -z "$out" ]; then
  ok "classifier: identical before/after (empty delta) -> rc 1, no output"
else
  bad "classifier: empty delta -> expected rc 1 and empty stdout, got rc $rc, stdout='$out'"
fi

hdr "classifier: mixed, deletions and renames (tree-diff semantics)"

D="$WORK/repo-mixed"; mkrepo "$D"
add_files "$D" CHANGELOG.md TODO.md
B="$(sha "$D")"
add_files "$D" frp-core/src/lib.rs
A="$(sha "$D")"
got="$(classify "$D" "$B" "$A")"; rc="${got%%	*}"; out="${got#*	}"
if [ "$rc" = "0" ] && [ "$out" = "frp-core/src/lib.rs" ]; then
  ok "classifier: mixed docs + one .rs -> rc 0, only the .rs path printed"
else
  bad "classifier: mixed delta -> expected rc 0 + 'frp-core/src/lib.rs', got rc $rc, stdout='$out'"
fi

D="$WORK/repo-delete"; mkrepo "$D"
add_files "$D" src/keep.rs src/gone.rs
B="$(sha "$D")"
rm -f "$D/src/gone.rs"
commit "$D" "delete gone.rs"
A="$(sha "$D")"
got="$(classify "$D" "$B" "$A")"; rc="${got%%	*}"; out="${got#*	}"
if [ "$rc" = "0" ] && [ "$out" = "src/gone.rs" ]; then
  ok "classifier: deletion of a measured path -> rc 0, deleted path printed"
else
  bad "classifier: deletion -> expected rc 0 + 'src/gone.rs', got rc $rc, stdout='$out'"
fi

D="$WORK/repo-rename"; mkrepo "$D"
add_files "$D" docs/notes.md
B="$(sha "$D")"
mkdir -p "$D/src"
git -C "$D" mv docs/notes.md src/notes.rs
commit "$D" "rename into the measured set"
A="$(sha "$D")"
got="$(classify "$D" "$B" "$A")"; rc="${got%%	*}"; out="${got#*	}"
if [ "$rc" = "0" ] && [ "$out" = "src/notes.rs" ]; then
  ok "classifier: rename docs -> .rs -> rc 0 (--no-renames surfaces delete+add), new path printed"
else
  bad "classifier: rename -> expected rc 0 + 'src/notes.rs', got rc $rc, stdout='$out'"
fi

hdr "classifier: error surface (rc 2 — never a silent skip)"

D="$WORK/repo-err"; mkrepo "$D"
add_files "$D" README.md
A="$(sha "$D")"
got="$(classify "$D" deadbeefdeadbeef "$A")"; rc="${got%%	*}"
if [ "$rc" = "2" ]; then
  ok "classifier: unresolvable before revision -> rc 2"
else
  bad "classifier: unknown revision -> expected rc 2, got rc $rc"
fi

rc=0; AB_REPO_DIR="$D" bash "$CLASSIFIER" >/dev/null 2>&1 || rc=$?
if [ "$rc" = "2" ]; then
  ok "classifier: no arguments -> rc 2"
else
  bad "classifier: no arguments -> expected rc 2, got rc $rc"
fi

rc=0; AB_REPO_DIR="$D" bash "$CLASSIFIER" "$A" >/dev/null 2>&1 || rc=$?
if [ "$rc" = "2" ]; then
  ok "classifier: one argument -> rc 2"
else
  bad "classifier: one argument -> expected rc 2, got rc $rc"
fi

mkdir -p "$WORK/not-a-repo"
rc=0; AB_REPO_DIR="$WORK/not-a-repo" bash "$CLASSIFIER" "$A" "$A" >/dev/null 2>&1 || rc=$?
if [ "$rc" = "2" ]; then
  ok "classifier: AB_REPO_DIR outside any git repo -> rc 2"
else
  bad "classifier: non-repo AB_REPO_DIR -> expected rc 2, got rc $rc"
fi

hdr "gate arithmetic: the published value is the MEDIAN, never the minimum"

# probe <AB_GATE_ENFORCE> <body> [<summary-file>]
# Sources the real gate definitions (AB_MATRIX_LIB_ONLY=1 stops the script
# before it provisions anything) and runs <body> against them.
probe() {
  local enforce="$1" body="$2" summary="${3:-}"
  AB_MD_MATRIX="$MATRIX" AB_MATRIX_LIB_ONLY=1 GATE_PCT="${GATE_PCT:-5}" \
  AB_GATE_ENFORCE="$enforce" GITHUB_STEP_SUMMARY="$summary" \
    bash -c 'source "$AB_MD_MATRIX"; '"$body"
}

got="$(probe 0 'gate_median 18.0 15.2 19.5')"
if [ "$got" = "18.0" ]; then
  ok "gate_median(18.0 15.2 19.5) = 18.0 (not the minimum 15.2)"
else
  bad "gate_median(18.0 15.2 19.5) -> expected 18.0, got '$got'"
fi

got="$(probe 0 'gate_median 10 20')"
if [ "$got" = "15.0" ]; then
  ok "gate_median(10 20) = 15.0 (even count averages the two middle samples)"
else
  bad "gate_median(10 20) -> expected 15.0, got '$got'"
fi

got="$(probe 0 'gate_verdict 18.0 15.2 19.5')"
if [ "$got" = "18.0 3 pass" ]; then
  ok "gate_verdict(18.0 15.2 19.5) = '18.0 3 pass' — 3 samples, median published"
else
  bad "gate_verdict(18.0 15.2 19.5) -> expected '18.0 3 pass', got '$got'"
fi

got="$(probe 0 'gate_verdict -40.0 -3.0 -20.0')"
if [ "$got" = "-20.0 3 REGRESSED" ]; then
  ok "gate_verdict(-40.0 -3.0 -20.0) = '-20.0 3 REGRESSED' (minimum -40.0 is not published)"
else
  bad "gate_verdict(-40.0 -3.0 -20.0) -> expected '-20.0 3 REGRESSED', got '$got'"
fi

got="$(probe 0 'gate_verdict')"
if [ "$got" = "0 0 SKIP(no data)" ]; then
  ok "gate_verdict() with no samples = '0 0 SKIP(no data)'"
else
  bad "gate_verdict() -> expected '0 0 SKIP(no data)', got '$got'"
fi

hdr "gate reporting: informational by default, hard failure only under AB_GATE_ENFORCE=1"

sum="$WORK/summary.md"; : > "$sum"
out="$(probe 0 'gate_report plain 100.0 82.0 -18.0 3 REGRESSED; echo "FAIL=$FAIL"' "$sum")"
rc=$?
if [ "$rc" = "0" ] && printf '%s' "$out" | grep -q '::warning::' \
   && printf '%s' "$out" | grep -q 'FAIL=1' \
   && printf '%s' "$out" | grep -q -- '-18.0%'; then
  ok "gate_report REGRESSED without enforce -> rc 0, ::warning::, FAIL=1, median row printed"
else
  bad "gate_report REGRESSED without enforce -> rc $rc, output='$out' (want rc 0 + ::warning:: + FAIL=1)"
fi

if grep -q '| plain | 100.0 | 82.0 | -18.0% | REGRESSED (n=3) |' "$sum"; then
  ok "gate_report appends the markdown row to \$GITHUB_STEP_SUMMARY"
else
  bad "gate_report did not append the expected row to \$GITHUB_STEP_SUMMARY: $(cat "$sum")"
fi

out="$(probe 0 'gate_report plain 100.0 99.0 -1.0 3 pass; echo "FAIL=$FAIL"')"
rc=$?
if [ "$rc" = "0" ] && printf '%s' "$out" | grep -q 'FAIL=0' \
   && ! printf '%s' "$out" | grep -q '::warning::'; then
  ok "gate_report within gate -> rc 0, FAIL=0, no annotation"
else
  bad "gate_report within gate -> rc $rc, output='$out' (want rc 0 + FAIL=0, no ::warning::)"
fi

rc=0; probe 1 'gate_report plain 100.0 82.0 -18.0 3 REGRESSED' >/dev/null 2>&1 || rc=$?
if [ "$rc" = "1" ]; then
  ok "gate_report REGRESSED with AB_GATE_ENFORCE=1 -> rc 1 (hard failure restored)"
else
  bad "gate_report REGRESSED with AB_GATE_ENFORCE=1 -> expected rc 1, got rc $rc"
fi

rc=0; out="$(probe 0 'echo ran')" || rc=$?
if [ "$rc" = "0" ] && [ "$out" = "ran" ]; then
  ok "sourcing ab-matrix.sh with AB_MATRIX_LIB_ONLY=1 stops before any build (local run, no summary file)"
else
  bad "AB_MATRIX_LIB_ONLY=1 seam leaked into the build path: rc $rc, output='$out'"
fi

hdr "measurement loop: the published delta is the median of the samples taken"

# pair_probe <values-file> <body>
# Drives the REAL measure_pair_deltas retry loop with run_side replaced by a
# stub that yields the scripted mbps values in order (one per call), so the
# "median of every sample actually taken, never the minimum" rule is measured
# end to end rather than asserted about gate_verdict in isolation.
# Values are consumed in call order: before, after, [before, after] per confirm.
pair_probe() {
  local values="$1" body="$2"
  AB_MD_MATRIX="$MATRIX" AB_MATRIX_LIB_ONLY=1 GATE_PCT=5 CONFIRM_RETRIES=2 \
  AB_MD_STUB_VALUES="$values" AB_MD_STUB_N="$WORK/stub.n" \
    bash -c '
      source "$AB_MD_MATRIX"
      FRPS_A=x FRPC_A=x STRESS_A=x FRPS_B=x FRPC_B=x STRESS_B=x REPS=1 RDUR=1
      : > "$AB_MD_STUB_N"
      run_side() {
        local n; n="$(cat "$AB_MD_STUB_N")"
        echo $((n + 1)) > "$AB_MD_STUB_N"
        sed -n "$((n + 1))p" "$AB_MD_STUB_VALUES"
      }
      '"$body"
}

# 100 -> 60 (regressed), then two confirms 100->75 and 100->98. Deltas are
# -40.0 / -25.0 / -2.0; the published value must be the median -25.0, NOT the
# minimum -40.0 that the first shot produced.
printf '100\n60\n100\n75\n100\n98\n' > "$WORK/vals-a"
got="$(pair_probe "$WORK/vals-a" 'measure_pair_deltas false false false false plain; read -r m n v <<< "$(gate_verdict $PAIR_DELTAS)"; echo "$PAIR_DELTAS|$m $n $v|$PAIR_MEDIAN_A|$PAIR_MEDIAN_B"')"
if [ "$got" = "-40.0 -25.0 -2.0|-25.0 3 REGRESSED|100.0|75.0" ]; then
  ok "measure_pair_deltas: 3 samples published as median -25.0, not the minimum -40.0"
else
  bad "measure_pair_deltas median-of-samples -> got '$got' (want '-40.0 -25.0 -2.0|-25.0 3 REGRESSED|100.0|75.0')"
fi

# The row's before/after must be the medians of the samples the delta came
# from: before=100 (all three), after=median(60, 75, 98)=75.0. The old code
# spent two extra measure runs to print columns that did not match the delta.
if printf '%s' "$got" | grep -q '|100.0|75.0$'; then
  ok "measure_pair_deltas: row before/after are the medians of the same samples"
else
  bad "measure_pair_deltas row columns did not come from the sampled set: '$got'"
fi

# A confirm shot inside the gate proves the first regression was noise, so the
# loop stops there: 2 samples, median -20.0, still never -40.0.
printf '100\n60\n100\n100\n' > "$WORK/vals-b"
got="$(pair_probe "$WORK/vals-b" 'measure_pair_deltas false false false false plain; read -r m n v <<< "$(gate_verdict $PAIR_DELTAS)"; echo "$m $n $v"')"
if [ "$got" = "-20.0 2 REGRESSED" ]; then
  ok "measure_pair_deltas: a within-gate confirm stops the loop (2 samples, median -20.0)"
else
  bad "measure_pair_deltas early stop -> got '$got' (want '-20.0 2 REGRESSED')"
fi

# First shot within the gate: no confirm runs are paid for at all.
printf '100\n98\n' > "$WORK/vals-c"
got="$(pair_probe "$WORK/vals-c" 'measure_pair_deltas false false false false plain; read -r m n v <<< "$(gate_verdict $PAIR_DELTAS)"; echo "$m $n $v|$PAIR_DELTAS"')"
if [ "$got" = "-2.0 1 pass|-2.0" ]; then
  ok "measure_pair_deltas: a within-gate first shot takes exactly 1 sample"
else
  bad "measure_pair_deltas within-gate -> got '$got' (want '-2.0 1 pass|-2.0')"
fi

# A side that yields no measurement at all must leave the pair unmeasured
# rather than publishing a delta computed from a missing number.
printf '100\n0\n' > "$WORK/vals-d"
got="$(pair_probe "$WORK/vals-d" 'measure_pair_deltas false false false false plain; echo "[$PAIR_DELTAS] [$PAIR_MEDIAN_A] [$PAIR_MEDIAN_B]"')"
if [ "$got" = "[] [0] [0]" ]; then
  ok "measure_pair_deltas: an empty side publishes no delta (no divide by a missing sample)"
else
  bad "measure_pair_deltas with an empty side -> got '$got' (want '[] [0] [0]')"
fi

if [ "$SABOTAGE_CHILD" = "1" ]; then
  exit 0
fi

hdr "mutant matrix: neutering a property must turn this suite red"

ORIG_CLASSIFIER_HASH="$(hasher "$CLASSIFIER")"
ORIG_MATRIX_HASH="$(hasher "$MATRIX")"

# run_suite_against <classifier> <matrix>: sets child_rc / child_result.
# The child's own log is captured (never echoed: its "FAIL" lines would be
# counted by the CI guard that watches THIS run) and only its RESULT line is
# kept for diagnostics. Globals rather than a printed return value: a command
# substitution would run the child in a subshell and the diagnostics would be
# discarded with it.
child_rc=0
child_result=""
run_suite_against() {
  child_rc=0
  AB_MD_SABOTAGE_CHILD=1 AB_MD_CLASSIFIER="$1" AB_MD_MATRIX="$2" \
    bash "$self" >"$WORK/child.log" 2>&1 || child_rc=$?
  child_result="$(grep -m1 '^RESULT: ' "$WORK/child.log" 2>/dev/null || true)"
}

# mutant_red <label> <classifier> <matrix>
# The child must go red AND reach its own summary line. A child that dies on
# line 3 — an unusable mutant, a missing tool, a syntax error introduced by the
# sed — also exits non-zero, and booking that as "the mutant was caught" is
# exactly the vacuous pass this matrix exists to prevent.
mutant_red() {
  local label="$1"
  run_suite_against "$2" "$3"
  if [ "$child_rc" != "0" ] && [ -n "$child_result" ]; then
    ok "mutant: $label -> child red ($child_result)"
  else
    bad "mutant: $label -> child green or died before reporting a summary (rc $child_rc, $child_result)"
  fi
}

# mutant <src> <sed-expr> <dst>: prints dst, or empty when the mutation did not
# change the file (an inert mutation must not be mistaken for a passing check).
mutant() {
  local src="$1" expr="$2" dst="$3"
  sed "$expr" "$src" > "$dst" || return 1
  cmp -s "$src" "$dst" && return 1
  printf '%s' "$dst"
}

# 1. classifier forced to always skip
M1="$WORK/mutant-classifier-always-skip.sh"
{ printf 'exit 1\n'; cat "$CLASSIFIER"; } > "$M1"
mutant_red "classifier forced to always skip" "$M1" "$MATRIX"

# 2. verdict always passing
M2="$(mutant "$MATRIX" 's/if above_gate "\$median"; then result="REGRESSED"; fi/:/' "$WORK/mutant-matrix-always-pass.sh")"
if [ -n "$M2" ]; then
  mutant_red "gate_verdict forced to always pass" "$CLASSIFIER" "$M2"
else
  bad "mutant: gate_verdict forced to always pass -> the sed mutation was inert, so it proves nothing"
fi

# 3. median replaced by the minimum
M3="$(mutant "$MATRIX" 's/statistics\.median(v)/min(v)/' "$WORK/mutant-matrix-min.sh")"
if [ -n "$M3" ]; then
  mutant_red "gate_median forced to min" "$CLASSIFIER" "$M3"
else
  bad "mutant: gate_median forced to min -> the sed mutation was inert, so it proves nothing"
fi

# 4. enforce path removed
M4="$(mutant "$MATRIX" 's/\[\[ "\$AB_GATE_ENFORCE" == "1" \]\]/[[ "0" == "1" ]]/' "$WORK/mutant-matrix-no-enforce.sh")"
if [ -n "$M4" ]; then
  mutant_red "AB_GATE_ENFORCE path removed" "$CLASSIFIER" "$M4"
else
  bad "mutant: AB_GATE_ENFORCE path removed -> the sed mutation was inert, so it proves nothing"
fi

# revert proof: the mutants were copies
if [ "$(hasher "$CLASSIFIER")" = "$ORIG_CLASSIFIER_HASH" ] \
   && [ "$(hasher "$MATRIX")" = "$ORIG_MATRIX_HASH" ]; then
  ok "real scripts are byte-identical after the mutant matrix (mutants were copies)"
else
  bad "a real script changed during the mutant matrix — mutants must only ever write copies"
fi
