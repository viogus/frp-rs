#!/usr/bin/env bash
# =============================================================================
# Fixture checks for the A/B throughput gate's delta classifier and verdict
# (TODO.md:11075).
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
#      sources the real gate_median / gate_verdict / gate_report / gate_final
#      definitions (the source-only guard at the top of the script stops before
#      any worktree, build or server) and calls them.
#   3. scripts/ab-remote.sh — the transport that carries the two gate switches
#      to the VPS. It is run for real against a stub `ssh` that records the
#      remote command the VPS shell would receive, because ssh forwards no
#      environment: a deleted or reworded splice silently disables the `enforce`
#      re-arm, and hashing the file alone would not witness that.
#
#      The recorded command is then EXECUTED, not grepped: a stub `flock` and a
#      probe in place of scripts/ab-matrix.sh report the environment and the two
#      positional arguments the harness actually receives. Text matching was not
#      enough — a `#` comment or an extra ssh argv leaves the blessed chain in
#      the string while the remote shell never sets the variables (review round
#      3, F1) — and it was too strict, rejecting run calls that work (round 3,
#      F2, e.g. quoted arguments or an `env` prefix).
#
# It also carries a MUTANT MATRIX (the sabotage converse): each mutant copies
# one of the three real scripts, applies exactly the mutation that would neuter
# one property, and re-runs THIS SUITE as a child process against the mutant.
# The suite must then go red. A green child means the fixtures do not actually
# witness the property they claim to, and the check fails. A child that reds for
# an unrelated reason counts as a vacuous pass, so the transport mutant lives in
# a repo-shaped tree (ab-remote.sh resolves its root from $0), its failure has to
# name the splice, and an unmutated control of that same tree must pass. A sixth
# mutant deletes the switches from the EXECUTED command and leaves the blessed
# chain behind as a `#` comment — the exact form that used to satisfy text
# matching — so the replay is proved against the attack it replaced. Two
# further controls replay the run calls those rewrites send (quoted arguments, an
# `env` prefix): the witness must accept what
# executes and reject only what does not. The real
# scripts are never written to; the check "real scripts are byte-identical after
# the mutant matrix" is the revert proof.
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
REMOTE="${AB_MD_REMOTE:-$ROOT/scripts/ab-remote.sh}"

# The child runs invoked by the mutant matrix run every fixture EXCEPT the
# mutant matrix itself (which would recurse forever), so they have their own
# floor. Both floors count CHECKS RUN, not checks passed: a mutant run is
# expected to fail fixtures, and the floor must not paper over an early exit.
SABOTAGE_CHILD="${AB_MD_SABOTAGE_CHILD:-0}"
if [ "$SABOTAGE_CHILD" = "1" ]; then MIN_CHECKS=45; else MIN_CHECKS=53; fi

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

for tool in git sed cmp tr cut grep mktemp tar env; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FATAL: $tool not found" >&2; exit 1; }
done
python3 -c 'pass' 2>/dev/null || { echo "FATAL: python3 not found (the gate uses it)" >&2; exit 1; }

[ -f "$CLASSIFIER" ] || { echo "FATAL: classifier not found: $CLASSIFIER" >&2; exit 1; }
[ -f "$MATRIX" ]     || { echo "FATAL: gate script not found: $MATRIX" >&2; exit 1; }
[ -f "$REMOTE" ]     || { echo "FATAL: remote transport not found: $REMOTE" >&2; exit 1; }

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

# The enforcement site is gate_final — gate_report only records the verdict and
# never ends the run — so the re-arm is proved by driving the function the
# script itself ends with, through the same `if gate_final; then … else …`
# shape (the sourced script runs under `set -e`, so a bare `gate_final` at rc 1
# would abort the probe exactly as it would abort the script). A demoted gate
# whose re-arm is unreachable would be a promise nothing witnesses.
rc=0; out="$(probe 1 'FAIL=1; if gate_final; then echo "inner=0"; else echo "inner=1"; fi')" || rc=$?
if [ "$rc" = "0" ] && printf '%s' "$out" | grep -q 'A/B GATE FAILED' \
   && printf '%s' "$out" | grep -q 'inner=1'; then
  ok "gate_final: FAIL=1 under AB_GATE_ENFORCE=1 -> rc 1 (hard failure restored)"
else
  bad "gate_final under AB_GATE_ENFORCE=1 -> rc $rc, output='$out' (want the FAILED line and the rc-1 branch)"
fi

rc=0; out="$(probe 0 'FAIL=1; if gate_final; then echo "inner=0"; else echo "inner=1"; fi')" || rc=$?
if [ "$rc" = "0" ] && printf '%s' "$out" | grep -q 'A/B GATE REGRESSED (informational' \
   && printf '%s' "$out" | grep -q 'inner=0'; then
  ok "gate_final: FAIL=1 without enforce -> rc 0 and the informational tail"
else
  bad "gate_final informational -> rc $rc, output='$out' (want the REGRESSED (informational) tail and the rc-0 branch)"
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

hdr "remote transport: the gate switches reach the VPS command line"

# scripts/ab-remote.sh forwards the two switches because ssh carries no
# environment and ab-matrix.sh reads them *on the VPS*. The suite runs the real
# script against a stub `ssh` that records each remote command instead of
# connecting: no network, no VPS, but the splice is exercised rather than
# grepped, so a deleted/reworded splice fails a fixture (and the mutant matrix
# below proves the step would notice).
REMOTE_ROOT="$WORK/remote"
mkdir -p "$REMOTE_ROOT/bin" "$REMOTE_ROOT/bundle"
for side in after before; do
  for b in "target/release/frps" "target/release/frpc" \
           "scripts/frp-stress/target/release/frp-stress"; do
    mkdir -p "$REMOTE_ROOT/$side/$(dirname -- "$b")"
    printf '#!/bin/sh\nexit 0\n' > "$REMOTE_ROOT/$side/$b"
    chmod +x "$REMOTE_ROOT/$side/$b"
  done
done
printf 'stub-key\n' > "$REMOTE_ROOT/key"

cat > "$REMOTE_ROOT/bin/ssh" <<'FAKE_SSH'
#!/usr/bin/env bash
# Stub ssh: record the remote command and drain the piped tarball when this call
# is the upload, so the local `tar` sees no broken pipe. What the VPS shell runs
# is every argument after the destination, joined by single spaces — that is
# what ssh itself does — so the record is the command, not merely our last
# argument: with `$last` an extra trailing argv could carry the blessed chain
# while the executed command had none (review round 3, F1b). ONE DELIMITED
# RECORD PER CALL with embedded newlines flattened: joining every call into one
# string is how a pattern meant for the run call could be satisfied by the
# earlier mkdir call (review round 2, D-A1).
last=""
for a in "$@"; do last="$a"; done
case "$last" in
  'tar xf'*) cat >/dev/null 2>&1 || true ;;
esac
remote=""
seen_host=0
for a in "$@"; do
  if [ "$seen_host" = "1" ]; then
    remote="${remote}${remote:+ }${a}"
    continue
  fi
  case "$a" in *@*) seen_host=1 ;; esac
done
flat="$(printf '%s' "$remote" | tr '\n' ' ')"
printf '%s\n' "$flat" >> "$AB_MD_SSH_CAPTURE"
case "$last" in
  *ab-matrix.sh*) exit "${AB_MD_SSH_RC:-0}" ;;
esac
exit 0
FAKE_SSH
chmod +x "$REMOTE_ROOT/bin/ssh"

# Stub flock for the replay below: consume the options and the lock path, then
# run the command it was given. The recorded remote command is EXECUTED, so the
# fake flock has to get out of the way rather than fail the probe.
cat > "$REMOTE_ROOT/bin/flock" <<'FAKE_FLOCK'
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  case "$1" in
    -w|-E) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
[ "$#" -gt 0 ] && shift
exec "$@"
FAKE_FLOCK
chmod +x "$REMOTE_ROOT/bin/flock"

# The probe that stands in for scripts/ab-matrix.sh during a replay. It reports
# what the harness would have been handed: the two gate switches and the two
# positional arguments (the repetitions and the duration).
PROBE_MATRIX="$REMOTE_ROOT/probe-ab-matrix.sh"
cat > "$PROBE_MATRIX" <<'PROBE'
#!/usr/bin/env bash
printf 'PROBE ENFORCE=[%s] FORCE=[%s] ARGS=[%s][%s]\n' \
  "${AB_GATE_ENFORCE-unset}" "${AB_FORCE_MEASURE-unset}" "${1-unset}" "${2-unset}"
PROBE
chmod +x "$PROBE_MATRIX"

# run_remote <remote-script> <capture-file> <stub-ssh-rc> [<VAR=val>...]
# Prints the script's exit code; the recorded remote commands land in the
# capture file, one line per ssh call.
run_remote() {
  local remote="$1" capture="$2" ssh_rc="$3"; shift 3
  local rc=0
  : > "$capture"
  env -i PATH="$REMOTE_ROOT/bin:/usr/bin:/bin" HOME="$HOME" \
      AB_MD_SSH_CAPTURE="$capture" AB_MD_SSH_RC="$ssh_rc" \
      AB_VPS_HOST=stub.invalid AB_VPS_SSH_KEY="$REMOTE_ROOT/key" \
      AFTER_ROOT="$REMOTE_ROOT/after" BEFORE_ROOT="$REMOTE_ROOT/before" \
      "$@" \
      bash "$remote" 3 8 "$REMOTE_ROOT/bundle" >/dev/null 2>&1 || rc=$?
  printf '%s' "$rc"
}

# call_record <capture> <needle>: the ONE recorded ssh call whose remote command
# mentions <needle>. Empty when none matches (the run call is gone) and empty
# when several do (the needle no longer identifies a single call) — both are
# failures of the witness, so neither may fall through to a looser match.
call_record() {
  local n
  n="$(grep -cF -- "$2" "$1")" || true
  [ "$n" = "1" ] || return 0
  grep -F -m1 -- "$2" "$1"
}

PROBE_HOME="$WORK/probe-home"

# probe_splice <capture>: EXECUTE the capture's single run call — the record that
# names ab-matrix.sh — with the stub flock and the probe in place of the harness,
# and print what the harness was handed. Prints nothing when the run call is
# absent, ambiguous, or carries no `cd ~/<dir> &&` preamble to replay; each of
# those is a failure of this witness and the caller reports it as one.
probe_splice() {
  local capture="$1" rec rel out
  rec="$(call_record "$capture" 'ab-matrix.sh')"
  [ -n "$rec" ] || return 0
  rel="$(printf '%s' "$rec" | sed -n 's|^cd ~/\([^ ]*\) &&.*|\1|p')"
  [ -n "$rel" ] || return 0
  mkdir -p "$PROBE_HOME/$rel/scripts" || return 0
  cp "$PROBE_MATRIX" "$PROBE_HOME/$rel/scripts/ab-matrix.sh" || return 0
  out="$(cd "$WORK" && HOME="$PROBE_HOME" PATH="$REMOTE_ROOT/bin:/usr/bin:/bin" \
         bash -c "$rec" 2>/dev/null)" || true
  printf '%s' "$out"
}

# run_and_probe <remote-script> <enforce> <force>: ship through the transport
# with those switches, then replay its run call. Prints the probe's one-line
# report, or a transport-level sentence when the script never got that far (a
# mutant that cannot start is not evidence about the splice, and the mutant
# matrix requires the "MISSING from the run call" wording before it books a
# caught mutant).
run_and_probe() {
  local rc
  rc="$(run_remote "$1" "$cap" 0 AB_GATE_ENFORCE="$2" AB_FORCE_MEASURE="$3")"
  if [ "$rc" != "0" ]; then
    printf 'TRANSPORT-EXITED-%s-BEFORE-THE-RUN-CALL' "$rc"
    return 0
  fi
  probe_splice "$cap"
}

# accepted_record <rel> <tail>: a one-record capture holding the remote command
# a correctly rewritten transport would send. The acceptance controls below use
# these instead of rewriting the tree's ab-remote.sh: under the mutant matrix
# that file IS the mutant, so a rewrite would be inert or would test the
# mutant's own text rather than the rewrite under discussion.
accepted_record() {
  local rel="$1" tail="$2" out
  out="$WORK/accept-$rel.capture"
  printf 'cd ~/%s && AFTER_ROOT=$PWD/after BEFORE_ROOT=$PWD/base %s\n' "$rel" "$tail" > "$out"
  printf '%s' "$out"
}

cap="$WORK/ssh-capture"
# The witness is the environment and the arguments the harness RECEIVES, not the
# text of the command: a `#` comment or an extra ssh argv leaves the blessed
# chain in the string while the remote shell never sets the variables (review
# round 3, F1), so the recorded run call is replayed and the values are asserted.
want_enforce="PROBE ENFORCE=[1] FORCE=[0] ARGS=[3][8]"
got="$(run_and_probe "$REMOTE" 1 0)"
if [ "$got" = "$want_enforce" ]; then
  ok "ab-remote.sh: the replayed run command hands the harness AB_GATE_ENFORCE=1 AB_FORCE_MEASURE=0 and the args 3 8"
else
  bad "ab-remote.sh enforce=1 splice MISSING from the run call -> the replayed run command reported '$got' (want '$want_enforce'); a '#' comment or an extra ssh argv satisfies text matching while the harness still falls back to the defaults"
fi

want_default="PROBE ENFORCE=[0] FORCE=[0] ARGS=[3][8]"
got="$(run_and_probe "$REMOTE" 0 0)"
if [ "$got" = "$want_default" ]; then
  ok "ab-remote.sh: unset switches default to AB_GATE_ENFORCE=0 AB_FORCE_MEASURE=0 in the replayed run command (previous behaviour)"
else
  bad "ab-remote.sh default splice MISSING from the run call -> the replayed run command reported '$got' (want '$want_default')"
fi

# Acceptance controls (review round 3, F2): the witness must accept a transport
# rewritten in a way that still WORKS. Anchored text matching rejected both of
# these, so a maintainer who kept the splice while quoting it would have faced a
# red suite for correct code. Each control replays the run call that rewrite
# would send, so it stays a statement about the witness even when the tree's own
# ab-remote.sh is a mutant.
ACCEPT_DQ="$(accepted_record accept-dq \
  'AB_GATE_ENFORCE=1 AB_FORCE_MEASURE=0 flock -w 1800 ~/.ab-matrix.lock bash scripts/ab-matrix.sh "3" "8" 2>&1')"
got="$(probe_splice "$ACCEPT_DQ")"
if [ "$got" = "$want_enforce" ]; then
  ok "ab-remote.sh: a rewrite that quotes the args still EXECUTES the switches (the witness accepts working code)"
else
  bad "ab-remote.sh quoted-args rewrite -> the replayed run command reported '$got' (want '$want_enforce'); the witness rejects a functional transport"
fi
ACCEPT_ENV="$(accepted_record accept-env \
  'flock -w 1800 ~/.ab-matrix.lock env AB_GATE_ENFORCE=1 AB_FORCE_MEASURE=0 bash scripts/ab-matrix.sh '\''3'\'' '\''8'\'' 2>&1')"
got="$(probe_splice "$ACCEPT_ENV")"
if [ "$got" = "$want_enforce" ]; then
  ok "ab-remote.sh: a rewrite that prefixes env still EXECUTES the switches (the witness accepts working code)"
else
  bad "ab-remote.sh env-prefixed rewrite -> the replayed run command reported '$got' (want '$want_enforce'); the witness rejects a functional transport"
fi

rc="$(run_remote "$REMOTE" "$cap" 0 AB_GATE_ENFORCE=2)"
if [ "$rc" = "2" ] && [ ! -s "$cap" ]; then
  ok "ab-remote.sh: refuses AB_GATE_ENFORCE=2 with rc 2 before shipping anything"
else
  bad "ab-remote.sh AB_GATE_ENFORCE=2 -> rc $rc, capture $(wc -l < "$cap" | tr -d ' ') line(s) (want rc 2 and no ssh call)"
fi

rc="$(run_remote "$REMOTE" "$cap" 0 AB_FORCE_MEASURE=maybe)"
if [ "$rc" = "2" ] && [ ! -s "$cap" ]; then
  ok "ab-remote.sh: refuses AB_FORCE_MEASURE=maybe with rc 2 before shipping anything"
else
  bad "ab-remote.sh AB_FORCE_MEASURE=maybe -> rc $rc, capture $(wc -l < "$cap" | tr -d ' ') line(s) (want rc 2 and no ssh call)"
fi

rc="$(run_remote "$REMOTE" "$cap" 7)"
if [ "$rc" = "7" ]; then
  ok "ab-remote.sh: the VPS exit code is propagated (remote rc 7 -> local rc 7)"
else
  bad "ab-remote.sh exit-code propagation -> rc $rc (want the stub's rc 7)"
fi

if [ "$SABOTAGE_CHILD" = "1" ]; then
  exit 0
fi

hdr "mutant matrix: neutering a property must turn this suite red"

ORIG_CLASSIFIER_HASH="$(hasher "$CLASSIFIER")"
ORIG_MATRIX_HASH="$(hasher "$MATRIX")"
ORIG_REMOTE_HASH="$(hasher "$REMOTE")"

# run_suite_against <classifier> <matrix> [<remote>]: sets child_rc / child_result.
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
    AB_MD_REMOTE="${3:-$REMOTE}" \
    bash "$self" >"$WORK/child.log" 2>&1 || child_rc=$?
  child_result="$(grep -m1 '^RESULT: ' "$WORK/child.log" 2>/dev/null || true)"
}

# mutant_red <label> <classifier> <matrix> [<remote>]
# The child must go red AND reach its own summary line. A child that dies on
# line 3 — an unusable mutant, a missing tool, a syntax error introduced by the
# sed — also exits non-zero, and booking that as "the mutant was caught" is
# exactly the vacuous pass this matrix exists to prevent.
mutant_red() {
  local label="$1"
  run_suite_against "$2" "$3" "${4:-$REMOTE}"
  if [ "$child_rc" != "0" ] && [ -n "$child_result" ]; then
    ok "mutant: $label -> child red ($child_result)"
  else
    bad "mutant: $label -> child green or died before reporting a summary (rc $child_rc, $child_result)"
  fi
}

# mutant_red_naming <label> <classifier> <matrix> <remote> <needle>
# As mutant_red, but the child must also have red for the STATED reason: its log
# has to name <needle>. Without this, a mutant whose copy cannot start at all
# (wrong directory layout, missing sibling file) reds anyway and the check would
# book a vacuous pass — review round 2's V1, where a *pristine* copy outside the
# repo produced the very same "child red" the mutant was credited with.
mutant_red_naming() {
  local label="$1" needle="$5" hits=0
  run_suite_against "$2" "$3" "$4"
  hits="$(grep -cF -- "$needle" "$WORK/child.log" 2>/dev/null)" || true
  if [ "$child_rc" != "0" ] && [ -n "$child_result" ] && [ "$hits" != "0" ]; then
    ok "mutant: $label -> child red for the stated reason ($child_result)"
  else
    bad "mutant: $label -> rc $child_rc, $child_result, '$needle' seen ${hits}x (want a red child whose log names the splice as missing from a completed run)"
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

# 5. remote transport: the enforce/force splice deleted. ab-remote.sh is driven
# at runtime and carries the switches to the VPS, so a hash pin alone would not
# witness that they are still forwarded — the child reds on the transport
# fixtures instead. The mutant must live in a tree that LOOKS like the repo
# (scripts/ next to the script): ab-remote.sh resolves ROOT from $0 and copies
# "$SCRIPT_DIR/ab-matrix.sh", so a bare copy under $WORK dies at that cp and a
# child would red for the wrong reason. Hence the named-reason check and the
# unmutated control right after it.
MUT_TREE="$WORK/mutant-tree"
mkdir -p "$MUT_TREE/scripts"
cp "$MATRIX" "$MUT_TREE/scripts/ab-matrix.sh"
M5="$(mutant "$REMOTE" 's/AB_GATE_ENFORCE=\$AB_GATE_ENFORCE AB_FORCE_MEASURE=\$AB_FORCE_MEASURE //' "$MUT_TREE/scripts/ab-remote.sh")"
if [ -n "$M5" ]; then
  mutant_red_naming "ab-remote.sh enforce/force splice deleted" "$CLASSIFIER" "$MATRIX" "$M5" 'splice MISSING from the run call'
else
  bad "mutant: ab-remote.sh splice deleted -> the sed mutation was inert, so it proves nothing"
fi

# 6. remote transport: the switches deleted from the EXECUTED command while the
# blessed chain is left behind inside the same record as a `#` comment. This is
# review round 3's F1: the witness used to match the recorded text, so this
# mutant stayed green while the remote harness silently fell back to the `:-0`
# defaults. It is built with python3 rather than sed because it has to edit two
# separate places (drop the splice, append the decoy) and leave the record
# syntactically valid.
M6="$MUT_TREE/scripts/ab-remote-comment.sh"
python3 - "$REMOTE" "$M6" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src).read()
splice = ("   AB_GATE_ENFORCE=$AB_GATE_ENFORCE AB_FORCE_MEASURE=$AB_FORCE_MEASURE \\\n"
          "   flock -w 1800 ~/.ab-matrix.lock \\\n")
decoy_tail = "bash scripts/ab-matrix.sh '$REPS' '$DUR' 2>&1\")"
if splice not in text or decoy_tail not in text:
    sys.exit(3)
text = text.replace(splice, "   flock -w 1800 ~/.ab-matrix.lock \\\n")
text = text.replace(decoy_tail,
    "bash scripts/ab-matrix.sh '$REPS' '$DUR' 2>&1 "
    "# AB_GATE_ENFORCE=$AB_GATE_ENFORCE AB_FORCE_MEASURE=$AB_FORCE_MEASURE "
    "flock -w 1800 ~/.ab-matrix.lock bash scripts/ab-matrix.sh '$REPS' '$DUR'\")")
open(dst, "w").write(text)
PY
if [ -s "$M6" ] && ! cmp -s "$REMOTE" "$M6"; then
  mutant_red_naming "ab-remote.sh switches deleted, blessed chain left as a comment" "$CLASSIFIER" "$MATRIX" "$M6" 'splice MISSING from the run call'
else
  bad "mutant: ab-remote.sh switches deleted but chain kept in a comment -> the mutation was inert (its anchor text is stale), so it proves nothing"
fi

# converse control for #5: the same layout, unmutated, must pass. Without it the
# check above would also be satisfied by a tree that reds at startup for a
# layout reason, which is exactly how the previous bare-$WORK mutant was
# vacuous.
CTL_TREE="$WORK/control-tree"
mkdir -p "$CTL_TREE/scripts"
cp "$MATRIX" "$CTL_TREE/scripts/ab-matrix.sh"
cp "$REMOTE" "$CTL_TREE/scripts/ab-remote.sh"
run_suite_against "$CLASSIFIER" "$MATRIX" "$CTL_TREE/scripts/ab-remote.sh"
if [ "$child_rc" = "0" ] && [ "$child_result" = "RESULT: 45 fixture check(s) hold" ]; then
  ok "control: the mutant's tree with an unmutated ab-remote.sh passes ($child_result)"
else
  bad "control: the mutant's tree unmutated -> rc $child_rc, $child_result (want rc 0 and RESULT: 45 fixture check(s) hold)"
fi

# revert proof: the mutants were copies
if [ "$(hasher "$CLASSIFIER")" = "$ORIG_CLASSIFIER_HASH" ] \
   && [ "$(hasher "$MATRIX")" = "$ORIG_MATRIX_HASH" ] \
   && [ "$(hasher "$REMOTE")" = "$ORIG_REMOTE_HASH" ]; then
  ok "real scripts are byte-identical after the mutant matrix (mutants were copies)"
else
  bad "a real script changed during the mutant matrix — mutants must only ever write copies"
fi
