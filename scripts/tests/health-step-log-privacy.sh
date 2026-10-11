#!/usr/bin/env bash
# health-step-log-privacy.sh — the reproducer and guard for the `health` job's
# fixture-step log paths (the `health` fixture-flake item, TODO.md line 11985).
#
# This header deliberately writes that reference as prose rather than as a
# `path:line` token: such a token here would be a new cite into the
# point-in-time set that `scripts/tests/pathline-cite-guard.sh` pins by count
# and identity, and its own table would then need a regeneration for a
# traceability comment. The item itself is still covered by
# `scripts/tests/todo-cite-guard.sh` everywhere it is cited by number.
#
# The shape it pins. Before the fix, nine of the health job's thirteen fixture
# steps wrote their suite's output to one fixed path under /tmp and then judged
# that path:
#
#     log=/tmp/frp-<step>.log
#     bash scripts/tests/<suite>.sh > "$log" 2>&1 || status=1
#     guard_log=$(<"$log")
#     ... count the '  ok ' lines in "$guard_log", require its RESULT: line ...
#
# The path is process-global, so two concurrent runs of the same step open the
# same file. Both runs redirect with `>`, and a truncating redirect does not
# reset the *other* writer's file offset: the second run's truncate destroys the
# first run's prefix, and the first run's later writes — including its final
# `RESULT: <n> fixture check(s) hold` line — then land past the resulting NUL
# hole. The first run reads its log with `$(<"$log")`, and a command
# substitution drops NUL bytes, so it sees the second run's (partial) prefix
# followed by its own tail: a count far below `guard_exact` and, depending on
# where the hole falls, a missing RESULT line. Either way `status=1`, the step
# prints its `::error::` line, and by the time it prints the diagnostic it
# re-reads the same path, now complete again — which is how a step can exit 1
# "while its own log printed RESULT: 269 fixture check(s) hold" (the M-33
# record, and the shape of two of the four recorded occurrences).
#
# Measured on an 8-core host with concurrent `cargo test` sweeps, shipped bodies:
#
#   * base tree, three concurrent cargo lanes plus two back-to-back full 13-step
#     sweeps plus a hot lane on steps 02/06/09/11: 12 red step-runs out of 237
#     (steps 02, 06 and 08), whole rounds otherwise green — a flake, not a
#     deterministic failure;
#   * step 6's body with the shipped path, two concurrent lanes: `status=1` with
#     `ok=108 result=1 fail=0 exact=269` (round 4) and `ok=232/237` (round 2);
#   * the same body with only `.$$` inserted before the extension, same host,
#     same rounds, same contention: 0 reds in 32 lane-runs (16 paired + 16
#     staggered), every one of them `ok=269 result=1 status=0`, against 6 red /
#     32 for the shipped path (4 red / 16 paired, 2 red / 16 staggered; the six
#     partial reads saw 108, 108, 232, 237, 252 and 259 `  ok` lines). An
#     independent reviewer rebuilt the two-arm control from scratch and measured
#     6 red / 12 staggered lane-runs for the shipped path against 0 red / 12 for
#     `.$$`.
#
# The fix is therefore one token per path: make the path per-run. `$$` in a
# /tmp path is this repo's established idiom for exactly this (see
# scripts/tests/rss-soak-run-dir.sh, scripts/tests/inner-feature-port-probe.sh,
# scripts/remote-frps.sh).
#
# What this file checks, in order:
#
#   1. the workflow exists; the `health:` job exists; and the workflow declares
#      exactly one top-level `health:` key, so a second copy cannot be guarded
#      only by luck of ordering;
#   2. the extracted region still hashes to `guard_region_pin` (the job's text);
#   3. the region declares 13 run blocks, names 11 distinct /tmp/frp tokens, and
#      each of those tokens occurs exactly once. That trio pins the current
#      *spelling* — deliberately, so the paths in this job cannot be renamed
#      silently — but it is not the property:
#
#          log="${TMPDIR:-/tmp}/frp-rss-soak-run-dir.log"
#          log_dir=/tmp/frp2-hidden; log=$log_dir/rss-soak.log
#
#      both pass it, and the three `${TMPDIR:-/tmp}` steps in this job are
#      outside the token list by design. The word "assigned" in check 3 means
#      "the token text occurs once", not "one assignment site": that is what the
#      variable-level checks below establish;
#   4. the region is the only job referencing each of the 13 suites the job
#      drives — in code, comment lines stripped. A renamed copy of the block
#      invoking the same suites reds here, and the failure names the copy's job
#      key;
#   5. every log variable spelled as a quoted `"$var"` target is discovered from
#      the block's own text (a `>`/`>>`/`>|` target, a `$(<file)` source, a
#      `cat` argument), evaluated in the block's own assignment context in two
#      separate shells, and required to differ. This is a pin on the *spelling*
#      the current steps use, not on the property: it sees only quoted-variable
#      targets, so a redirect written as a fixed literal is invisible to it;
#   6. every redirect/pipe *target word* in every run block — the invariant, and
#      the reason this file exists. The scanner below reads each block with its
#      comments stripped and reports its `>`/`>>`/`>|`/`&>` targets, its
#      `| tee <target>` arguments, its `dd of=<target>` and its read sides
#      (`$(<file)`, `cat <file>`); a quoted case label such as `'-> child red'`
#      is a word, not a redirect. Each non-exempt word is then evaluated as a
#      shell word in the block's own leading-assignment context, in two separate
#      shells, and required to differ — so a fixed literal target
#      (`| tee "$log" >> /tmp/shared.log`, `dd of=/tmp/shared`,
#      `bash ... > /tmp/anything.log`) reds on its own, naming the block, the
#      target and both evaluated values, with `guard_region_pin` left at the
#      unmodified job's hash. These values are also required to be pairwise
#      distinct across all steps;
#   7. every evaluated log path sits in an existing parent directory. This is
#      what refuses
#
#          log=/tmp/frp-rss-soak-run-dir.$$.log/tmp/frp-rss-shared.log
#
#      whose real path's parent is the per-run `...$$.log` component, a file.
#      Measured with the shipped step-6 body and only that assignment changed:
#      the redirect fails with "/tmp/frp-rss-soak-run-dir.<pid>.log/tmp/
#      frp-rss-shared.log: No such file or directory", the suite never runs, and
#      under the body's own `set -e` the read-back stops the step with rc 1
#      before its `::error::` line. A path whose parent does not exist cannot be
#      a log this job writes, and no step in this job `mkdir`s its log's parent,
#      so "the parent exists" is a true invariant here;
#   8. enforcer canaries: known-answer inputs for the per-run predicate, the
#      distinctness comparison, the parent-directory rule and the target scanner
#      itself, each with one input it must accept and one it must refuse.
#
# Exemptions are explicit and complete: an fd-duplication operator (`>&N`,
# `2>&1`, `&N`) has no path and is not a target; and a target whose evaluated
# value is `/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/fd/*` or `-` is a
# sink, not a shared log. Nothing else is exempt. An earlier revision discovered
# targets only by quoted-`"$var"` spelling, which left the review's
# `| tee "$log" >> /tmp/shared.log` recipe green with a genuinely shared fixed
# path; the word-level scan is what closes that, and it is deliberately not
# implemented as a wider grep pattern.
#
# Residual limits, stated rather than implied: this scanner is line-oriented, so
# a path assembled inside a function body or by `eval` at a level it does not
# reach, process substitution (`>(...)`), a target handed to a wrapper that
# redirects on its caller's behalf, and `set -x` trace output are not seen. Each
# would need a new shape here, not a wider exemption list.
#
# Unwired and self-unhashed, on purpose. Adding this file as a CI step would
# renumber every numeric `.github/workflows/ci.yml` citation that live files
# carry — the reason `scripts/tests/inner-feature-port-probe.sh` records for
# staying unwired. And nothing pins *this* file: the region pin pins the job, so
# a commit that reverts a `log=` value and edits this guard to match is caught
# by nothing automatic. What catches that is review of any PR touching the
# health job, plus running this guard by hand and comparing the
# `guard self-hash` line it prints (on the success path) with the sha256
# recorded in the PR record and the round's development-log entry. The
# self-hash is checked to be computable from a readable regular file, so a
# failed self-hash is a red run, not a skipped line.
#
# Run it by hand after touching the health job:
#
#     bash scripts/tests/health-step-log-privacy.sh
#
# `guard_region_pin` is the sha256 of the `health:` job's text in
# .github/workflows/ci.yml (that job only, so unrelated workflow edits do not
# red this file). Recompute it with the same extractor this file checks with,
# never by hand:
#
#     bash scripts/tests/health-step-log-privacy.sh --print-region-hash
#
# Usage: bash scripts/tests/health-step-log-privacy.sh
set -uo pipefail

# `--print-region-hash` exists so the pin can only be recomputed with the same
# extractor that verifies it. It returns before the check floor is armed, because
# it reports a pin rather than asserting one.
print_region_hash=0
if [ "${1:-}" = "--print-region-hash" ]; then
    print_region_hash=1
fi

self_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$self_dir/../.." && pwd)
workflow="$repo_root/.github/workflows/ci.yml"

# --- the health job's text, extracted the one way this file knows -------------
# The region is the `health:` job: its key line and every following line up to the
# next two-space job key. Comments are kept (the token scan strips them per line).
extract_region() {
    awk '
        /^  health:$/ { in_job = 1 }
        in_job && /^  [A-Za-z0-9_-]+:$/ && !/^  health:$/ { exit }
        in_job { print }
    ' "$workflow"
}

# --- self-defence: assert a floor on every exit path --------------------------
# A suite that silently stops checking must not exit green: `exit "$fails"` alone
# is happy with `RESULT: 0 fixture check(s) hold`. The floor is the measured check
# count of a green run, so deleting any check below drops the count under it.
# A floor of 0 (or an unset floor, or an all-zero spelling) would disable the
# guard from inside, so each of those is itself a failure.
MIN_CHECKS=82
checks=0
fails=0

ok() {
    checks=$((checks + 1))
    printf '  ok    %s\n' "$1"
}
bad() {
    checks=$((checks + 1))
    fails=$((fails + 1))
    printf '  FAIL  %s\n' "$1"
}
floor_check() {
    if [ -z "${MIN_CHECKS:-}" ] || [ "$MIN_CHECKS" = "0" ]; then
        printf '  FAIL  the check floor is missing or zero (MIN_CHECKS=%s)\n' "${MIN_CHECKS:-}"
        exit 1
    fi
    if [ "$checks" -lt "$MIN_CHECKS" ]; then
        printf '  FAIL  only %s check(s) ran, below the floor of %s: a scenario was skipped, not run, or swallowed\n' \
            "$checks" "$MIN_CHECKS"
        exit 1
    fi
}

# --- hasher: absolute and vector-proven --------------------------------------
# Same candidate order, same known vector and the same fail-closed mode as the
# CI steps this file guards. `command -v sha256sum` honours a shell function and
# then $PATH, so a shim planted earlier on PATH could return the pinned digest
# for bytes that changed while this check "passed".
guard_hasher=''
guard_abc=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
for cand in /usr/bin/sha256sum /bin/sha256sum /sbin/sha256sum /usr/sbin/sha256sum /usr/local/bin/sha256sum; do
    [ -x "$cand" ] || continue
    probe=$(printf 'abc' | "$cand" 2>/dev/null)
    [ "${probe%% *}" = "$guard_abc" ] || continue
    guard_hasher=$cand
    break
done
if [ -z "$guard_hasher" ]; then
    for cand in /usr/bin/shasum /bin/shasum /usr/local/bin/shasum; do
        [ -x "$cand" ] || continue
        probe=$(printf 'abc' | "$cand" -a 256 2>/dev/null)
        [ "${probe%% *}" = "$guard_abc" ] || continue
        guard_hasher="$cand -a 256"
        break
    done
fi
# `${out%% *}` is a shell expansion, so no PATH lookup (an `awk` shim, say) stands
# between the absolute, vector-proven hasher and the digest it reports.
sha_of() {
    local out
    out=$(printf '%s' "$1" | $guard_hasher)
    printf '%s\n' "${out%% *}"
}

if [ "$print_region_hash" = "1" ]; then
    if [ -z "$guard_hasher" ]; then
        printf 'health-step-log-privacy: no sha256 tool found (tried sha256sum then shasum -a 256)\n' >&2
        exit 2
    fi
    if [ ! -f "$workflow" ]; then
        printf 'health-step-log-privacy: %s does not exist\n' "$workflow" >&2
        exit 2
    fi
    printf '%s\n' "$(sha_of "$(extract_region)")"
    exit 0
fi

# The target scanner below is python3 (the repo's other script suites use the
# same interpreter). A missing interpreter is a red run, never a skipped check:
# the check it performs is the invariant this file exists for.
if ! command -v python3 >/dev/null 2>&1; then
    printf 'FAIL  python3 is required by the redirect-target scanner and was not found\n' >&2
    exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/health-log-privacy.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap 'floor_check; cleanup; exit "$fails"' EXIT

# --- self-identity ------------------------------------------------------------
# The region pin pins the health job, not this file. Nothing pins this guard, so
# its own digest is printed on the success path for the PR record and the round's
# development-log entry, and a self-hash that cannot be computed (unreadable $0,
# no hasher) is a failure rather than a skipped line.
self_path="$self_dir/$(basename -- "${BASH_SOURCE[0]}")"
self_file_ok=0
if [ -f "$self_path" ] && [ -r "$self_path" ]; then
    self_file_ok=1
    ok "this guard's own file is a readable regular file ($self_path)"
else
    bad "this guard's own file is not a readable regular file ($self_path): the self-hash cannot be trusted"
fi
guard_self_sha=''
if [ -n "$guard_hasher" ] && [ "$self_file_ok" = "1" ]; then
    self_out=$($guard_hasher < "$self_path" 2>/dev/null)
    guard_self_sha=${self_out%% *}
fi
self_hash_ok=1
[ -n "$guard_self_sha" ] || self_hash_ok=0
[ "${#guard_self_sha}" = "64" ] || self_hash_ok=0
case "$guard_self_sha" in
    *[!0-9a-f]*) self_hash_ok=0 ;;
esac
if [ "$self_hash_ok" = "1" ]; then
    ok "this guard's own sha256 was computed with the same absolute hasher ($guard_self_sha)"
else
    bad "this guard's own sha256 could not be computed (got '${guard_self_sha:-<empty>}')"
fi

# --- the predicate under test -------------------------------------------------
# A token is run-unique when it carries a per-run component: the same token text
# evaluated in two different processes must yield two different paths. `$$` is
# what makes that true; a token with no `$`, or with a `$` construct other than
# `$$` (which this check cannot evaluate safely), is refused rather than judged.
token_is_run_unique() {
    local token="$1" first second
    case "$token" in
        *'$'*) ;;
        *) return 1 ;;
    esac
    case "${token//\$\$/}" in
        *'$'*) return 1 ;;
    esac
    first=$(eval "printf '%s' \"$token\"")
    second=$(bash -c 'tok=$1; eval "printf '%s' \"\$tok\""' _ "$token")
    [ "$first" != "$second" ]
}

# True only for two or more values that are pairwise different, so a scan that
# collapsed to one path cannot report itself as distinct.
list_is_distinct() {
    local -a vals=("$@")
    local i j
    [ "${#vals[@]}" -ge 2 ] || return 1
    for ((i = 0; i < ${#vals[@]}; i++)); do
        for ((j = i + 1; j < ${#vals[@]}; j++)); do
            [ "${vals[$i]}" = "${vals[$j]}" ] && return 1
        done
    done
    return 0
}

# --- preflight ----------------------------------------------------------------
if [ -f "$workflow" ]; then
    ok 'the workflow under test exists (.github/workflows/ci.yml)'
else
    bad "the workflow under test is missing: $workflow"
fi

region=$(extract_region)
case "$region" in
    *'name: Health'*) ok 'the health job was located and carries its name line' ;;
    *) bad 'the health job could not be located (no `name: Health` in the region)' ;;
esac

# `extract_region` stops at the first `^  health:$` it finds, so a second
# top-level `health:` key would leave whatever follows it unguarded while this
# file stayed green. Assert the count. (A *renamed* copy is caught by the
# whole-file ownership checks further down, not here.)
health_keys=$(grep -cE '^  health:$' "$workflow" 2>/dev/null || true)
health_keys=${health_keys:-0}
if [ "$health_keys" = "1" ]; then
    ok 'the workflow declares exactly one top-level health job key'
else
    bad "the workflow declares $health_keys top-level health job keys: only one is read, so a second copy could carry a reverted path unnoticed"
fi

guard_region_pin=4eb650cf8a3afd5bacf4d2794a43d02c1313004bf255a9c3847ff63b20297ca6
region_pin=$(sha_of "$region")
if [ "$region_pin" = "$guard_region_pin" ]; then
    ok "the health job's text still hashes to the pinned region ($guard_region_pin)"
    printf 'pinned regions verified 1/1: health-job-log-paths\n'
else
    bad "the health job's text changed (pin $guard_region_pin, now $region_pin): re-read the paths below, then recompute the pin with --print-region-hash"
fi

if [ -n "$guard_hasher" ]; then
    ok "an absolute sha256 hasher was resolved and proved against the abc vector ($guard_hasher)"
else
    bad 'no absolute sha256 hasher could be proved against the abc vector'
fi

guard_steps=13
# Both spellings GitHub accepts here: 12 steps use the block form `run: |` and
# step 1 is inline (`run: bash scripts/repo-health.sh`). A non-anchored match is
# not a count of steps — `--dry-run:` and prose also contain the substring.
step_count=$(printf '%s\n' "$region" | grep -cE '^[[:space:]]+run:')
if [ "$step_count" = "$guard_steps" ]; then
    ok "the health job still declares $guard_steps run blocks"
else
    bad "the health job declares $step_count run blocks, not the pinned $guard_steps"
fi

# --- the live paths -----------------------------------------------------------
# Comment lines are stripped: the job's prose names a /tmp path in a comment, and
# a comment is not a writer. Everything else under /tmp/frp is a path some step
# hands to a shell.
live=$(printf '%s\n' "$region" | grep -v '^[[:space:]]*#')
tokens=()
while IFS= read -r token; do
    tokens+=("$token")
done < <(printf '%s\n' "$live" | grep -oE '/tmp/frp[A-Za-z0-9_.$-]*' | sort -u)

guard_path_count=11
if [ "${#tokens[@]}" = "$guard_path_count" ]; then
    ok "the health job names exactly $guard_path_count distinct /tmp/frp paths"
else
    bad "the health job names ${#tokens[@]} distinct /tmp/frp paths, not the pinned $guard_path_count"
fi

once=1
for token in ${tokens[@]+"${tokens[@]}"}; do
    occurrences=$(printf '%s\n' "$live" | grep -oF -- "$token" | wc -l | tr -d ' ')
    if [ "$occurrences" != "1" ]; then
        once=0
        bad "the path $token is assigned $occurrences times, not once"
    fi
done
if [ "$once" = "1" ]; then
    ok 'each of the 11 /tmp/frp path tokens occurs exactly once in the job (a per-token occurrence check; the variable-level checks below are the assignment-level invariant)'
fi

values=()
for token in ${tokens[@]+"${tokens[@]}"}; do
    case "${token//\$\$/}" in
        *'$'*)
            bad "the path $token carries a shell construct other than \$\$ (refusing to evaluate it)"
            continue
            ;;
    esac
    if token_is_run_unique "$token"; then
        values+=("$(eval "printf '%s' \"$token\"")")
        ok "$token evaluates to a per-run path ($(eval "printf '%s' \"$token\""))"
    else
        bad "the path $token has no per-run component: two concurrent runs of this step share it"
    fi
done

if list_is_distinct ${values[@]+"${values[@]}"}; then
    ok "all ${#values[@]} evaluated paths are distinct within one run"
else
    bad "the ${#values[@]} evaluated path token(s) are not pairwise distinct in one run (a token evaluates to the same file as another)"
fi

# --- whole-file ownership: the region is the only job running these suites ----
# `extract_region` reads only the health block, so a second job — a renamed copy
# of the block, say — could invoke the same suites (and carry one reverted path)
# while every check above stayed green. Every non-comment reference to each suite
# the job drives must therefore sit inside the region, and the region must
# reference all 13. `scripts/repo-health.sh` is named in comments outside the
# job; only comment-stripped references count.
region_start=$(grep -nE '^  health:$' "$workflow" 2>/dev/null | head -n 1 | cut -d: -f1)
region_start=${region_start:-0}
region_end=0
if [ "$region_start" -gt 0 ] && [ -f "$workflow" ]; then
    region_end=$(awk -v s="$region_start" 'NR > s && /^  [A-Za-z0-9_-]+:$/ { print NR - 1; exit }' "$workflow")
    if [ -z "$region_end" ]; then
        region_end=$(wc -l < "$workflow" | tr -d ' ')
    fi
fi

guard_suites=(
    scripts/repo-health.sh
    scripts/tests/repo-health-fixtures.sh
    scripts/tests/compat-stray-guard.sh
    scripts/tests/compat-port-ownership.sh
    scripts/tests/compat-scenario-retry.sh
    scripts/tests/rss-soak-run-dir.sh
    scripts/tests/large-functions-classifier.sh
    scripts/tests/docs-go-column.sh
    scripts/tests/remote-frps-reap.sh
    scripts/tests/todo-cite-guard.sh
    scripts/tests/todo-cite-guard-fixtures.sh
    scripts/tests/ab-measurable-delta.sh
    scripts/tests/pathline-cite-fixtures.sh
)
guard_suite_count=13
if [ "${#guard_suites[@]}" = "$guard_suite_count" ]; then
    ok "the guard names all $guard_suite_count suites the health job drives"
else
    bad "the guard names ${#guard_suites[@]} suites, not the pinned $guard_suite_count"
fi
for suite in ${guard_suites[@]+"${guard_suites[@]}"}; do
    in_region=$(awk -v s="$region_start" -v e="$region_end" -v p="$suite" '
        NR >= s && NR <= e && $0 !~ /^[[:space:]]*#/ && index($0, p) > 0 { c++ }
        END { print c + 0 }
    ' "$workflow" 2>/dev/null)
    outside=$(awk -v s="$region_start" -v e="$region_end" -v p="$suite" '
        /^  [A-Za-z0-9_-]+:$/ { job = $0; sub(/^[[:space:]]+/, "", job); sub(/:[[:space:]]*$/, "", job) }
        (NR < s || NR > e) && $0 !~ /^[[:space:]]*#/ && index($0, p) > 0 { print NR ":" job }
    ' "$workflow" 2>/dev/null)
    if [ -n "$outside" ]; then
        bad "$suite is referenced outside the health job at $outside: this guard reads only the health block, so a copy there could carry a reverted path"
    elif [ "${in_region:-0}" = "0" ]; then
        bad "$suite is never referenced inside the health job (the region or the suite list is stale)"
    else
        ok "the health job is the only job referencing $suite ($in_region comment-stripped reference(s) inside the region)"
    fi
done

# --- the log variables, discovered from each block's own text ------------------
# The token list above is a spelling pin; this is the invariant. Each run block's
# body is parsed out of the region, and every variable that block uses as a log
# is discovered from usage — a `>`/`>>`/`>|` target, a `$(<file)` source, a `cat`
# argument — then evaluated in that block's own assignment context (the leading
# assignments of its body, not a bare `eval`) in two separate shells.
mkdir -p -- "$work/blocks"
printf '%s\n' "$region" > "$work/region.txt"
awk -v dir="$work/blocks" '
    function close_block() { if (open_) { close(f); open_ = 0 } }
    /^[[:space:]]+run:/ {
        close_block()
        match($0, /^[ ]+/); ind = RLENGTH
        n++
        f = dir "/block-" n ".body"
        open_ = 1
        run_ind = ind
        rest = substr($0, ind + 1)
        sub(/^run:[[:space:]]*/, "", rest)
        if (rest != "" && rest != "|" && rest != "|-" && rest != "|+" && rest != ">" && rest != ">-") {
            print "# inline run: " rest > f
        }
        next
    }
    open_ {
        if ($0 ~ /^[[:space:]]*$/) { print "" > f; next }
        match($0, /^[ ]*/); ind2 = RLENGTH
        if (ind2 > run_ind) { print substr($0, run_ind + 3) > f; next }
        close_block()
    }
    END { close_block(); printf "%d\n", n + 0 > (dir "/count") }
' "$work/region.txt"
guard_blocks=0
if [ -f "$work/blocks/count" ]; then
    guard_blocks=$(cat "$work/blocks/count")
fi

# The discovery patterns. `[{]`/`[}]` are literal braces: ERE interval syntax is
# not involved, so they mean the same thing to every grep this repo runs.
block_var_names() {
    local body="$1"
    {
        grep -oE '>>?[[:space:]]*"\$[{]?[A-Za-z_][A-Za-z0-9_]*[}]?"' "$body"
        grep -oE '>\|[[:space:]]*"\$[{]?[A-Za-z_][A-Za-z0-9_]*[}]?"' "$body"
        grep -oE '\$\(<"\$[{]?[A-Za-z_][A-Za-z0-9_]*[}]?"\)' "$body"
        grep -oE 'cat[[:space:]]+"\$[{]?[A-Za-z_][A-Za-z0-9_]*[}]?"' "$body"
    } 2>/dev/null | sed -E 's/.*\$[{]?([A-Za-z_][A-Za-z0-9_]*)[}]?"\)?$/\1/' | sort -u
}
# The body's own context: its leading assignments, stopping at the first line
# that is neither an assignment nor a harmless prelude line. This is what makes
# the evaluation "in the step's own context" rather than a bare `eval` of the
# token — a variable set from another variable is resolved as the step sets it.
block_context() {
    awk '
        /^[[:space:]]*$/ { next }
        /^[[:space:]]*#/ { next }
        /^set / { next }
        /^[A-Za-z_][A-Za-z0-9_]*=/ { print; next }
        { exit }
    ' "$1"
}
eval_in_context() {
    {
        cat "$1"
        printf 'printf "%%s" "$%s"\n' "$2"
    } > "$work/eval-body.sh"
    bash "$work/eval-body.sh" 2>/dev/null
}
# Evaluate one *word* (quotes and expansions included, as the block spells it) in
# the block's own context. This is what makes the word-level check see a literal
# target, a `"$dir"/x.log` mix and a `"$(mktemp)"` alike: the word is spliced
# into a printf in the block's assignment context, so the shell — not a pattern —
# decides what it means.
eval_word_in_context() {
    {
        cat "$1"
        printf 'printf "%%s" %s\n' "$2"
    } > "$work/eval-word.sh"
    bash "$work/eval-word.sh" 2>/dev/null
}

# The redirect/pipe target scanner. Discovery by *shape*, not by spelling: this
# is the check an earlier quoted-`"$var"`-only grep could not make. Output is one
# `op<TAB>kind<TAB>word` line per item, in file order, with comments stripped and
# quoted words skipped. kind is `target` (a redirect or pipe target), `read` (a
# `$(<file)` / `cat <file>` source) or `fddup` (an fd-duplication operator, which
# names no path). Exemptions are decided by the caller (operator for `fddup`,
# evaluated value for the `/dev` sinks and `-`), never by this scanner.
block_target_items() {
    python3 -B - "$1" <<'PY'
import sys


def strip_comment(line):
    """Drop an unquoted shell comment. `#` opens one at the start of a word."""
    out = []
    i, n = 0, len(line)
    quote = None
    while i < n:
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                out.append(c)
                i += 1
                if i < n:
                    out.append(line[i])
                    i += 1
                continue
            out.append(c)
            i += 1
            if c == quote:
                quote = None
            continue
        if c in ('"', "'"):
            quote = c
            out.append(c)
            i += 1
            continue
        if c == "\\":
            out.append(c)
            i += 1
            if i < n:
                out.append(line[i])
                i += 1
            continue
        if c == "#" and (i == 0 or line[i - 1] in " \t;&|("):
            break
        out.append(c)
        i += 1
    return "".join(out)


def read_word(line, i):
    """Read one shell word, quotes kept verbatim; stop at an unquoted operator."""
    out = []
    n = len(line)
    while i < n:
        c = line[i]
        if c in " \t":
            break
        if c in ";|&<>()":
            break
        if c == "$" and i + 1 < n and line[i + 1] == "(":
            break
        if c == "\\":
            out.append(c)
            i += 1
            if i < n:
                out.append(line[i])
                i += 1
            continue
        if c in ('"', "'"):
            q = c
            out.append(c)
            i += 1
            while i < n:
                d = line[i]
                if q == '"' and d == "\\":
                    out.append(d)
                    i += 1
                    if i < n:
                        out.append(line[i])
                        i += 1
                    continue
                out.append(d)
                i += 1
                if d == q:
                    break
            continue
        out.append(c)
        i += 1
    return "".join(out), i


def scan_line(line):
    """Return (op, kind, word) for every redirect/pipe item on one line."""
    res = []
    line = strip_comment(line)
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c in ('"', "'"):
            _, i = read_word(line, i)
            continue
        if c == "\\":
            i += 2
            continue
        if c == ">" and i + 1 < n and line[i + 1] == "&":
            j = i + 2
            w, j = read_word(line, j)
            res.append((">&", "fddup", w))
            i = j
            continue
        if c == "&" and i + 1 < n and line[i + 1] == ">":
            op = "&>>" if i + 2 < n and line[i + 2] == ">" else "&>"
            j = i + len(op)
            while j < n and line[j] in " \t":
                j += 1
            w, j = read_word(line, j)
            if w:
                res.append((op, "target", w))
            i = j
            continue
        if c == ">":
            op = ">"
            j = i + 1
            if j < n and line[j] == ">":
                op = ">>"
                j += 1
            elif j < n and line[j] == "|":
                op = ">|"
                j += 1
            while j < n and line[j] in " \t":
                j += 1
            w, j = read_word(line, j)
            if w:
                res.append((op, "target", w))
            i = j
            continue
        if c == "|" and not (i + 1 < n and line[i + 1] == "|"):
            j = i + 1
            while j < n and line[j] in " \t":
                j += 1
            w, j = read_word(line, j)
            if w == "tee":
                while True:
                    while j < n and line[j] in " \t":
                        j += 1
                    if j >= n or line[j] in ";|<>":
                        break
                    a, j2 = read_word(line, j)
                    j = j2
                    if a.startswith("-"):
                        continue
                    res.append(("tee", "target", a))
                    break
            i = j
            continue
        if c == "$" and line[i:i + 3] == "$(<":
            j = i + 3
            while j < n and line[j] in " \t":
                j += 1
            w, j = read_word(line, j)
            while j < n and line[j] in " \t":
                j += 1
            if j < n and line[j] == ")":
                j += 1
            if w:
                res.append(("$(<)", "read", w))
            i = j
            continue
        if c not in ";|&<>()":
            w, j = read_word(line, i)
            if w == "dd":
                k = j
                while k < n:
                    while k < n and line[k] in " \t":
                        k += 1
                    if k >= n or line[k] in ";|&<>":
                        break
                    a, k2 = read_word(line, k)
                    if a.startswith("of=") and len(a) > 3:
                        res.append(("dd-of", "target", a[3:]))
                    k = k2
                j = k
            elif w.startswith("of=") and len(w) > 3:
                res.append(("dd-of", "target", w[3:]))
            elif w == "cat":
                k = j
                while k < n and line[k] in " \t":
                    k += 1
                if k < n and line[k] not in ";|&<>":
                    a, k2 = read_word(line, k)
                    res.append(("cat", "read", a))
                    k = k2
                j = k
            i = j if j > i else i + 1
            continue
        i += 1
    return res


with open(sys.argv[1], errors="replace") as fh:
    for line in fh:
        for op, kind, word in scan_line(line):
            if word:
                sys.stdout.write("%s\t%s\t%s\n" % (op, kind, word))
PY
}

guard_log_vars=14
log_vars=()
log_values=()
block=0
while [ "$block" -lt "$guard_blocks" ]; do
    block=$((block + 1))
    body="$work/blocks/block-$block.body"
    if [ ! -f "$body" ]; then
        bad "run block $block has no parsed body (the block parser and the step counter disagree)"
        continue
    fi
    block_context "$body" > "$work/blocks/block-$block.ctx"
    while IFS= read -r var; do
        [ -n "$var" ] || continue
        log_vars+=("$block:$var")
        first=$(eval_in_context "$work/blocks/block-$block.ctx" "$var")
        second=$(eval_in_context "$work/blocks/block-$block.ctx" "$var")
        log_values+=("$first")
        if [ -z "$first" ]; then
            bad "the log variable $var in run block $block evaluates to nothing: its context or its spelling cannot produce a path"
        elif [ "$first" != "$second" ]; then
            ok "the log variable $var in run block $block is per-run (evaluated in its own context twice: $first)"
        else
            bad "the log variable $var in run block $block evaluates to the same path in two shells ($first): concurrent runs of this step share it"
        fi
    done < <(block_var_names "$body")
done

if [ "${#log_vars[@]}" = "$guard_log_vars" ]; then
    ok "the job's $guard_blocks run blocks name $guard_log_vars log variables, discovered from usage rather than from spelling"
else
    bad "the job's run blocks name ${#log_vars[@]} log variables, not the pinned $guard_log_vars (parsed $guard_blocks block(s)): a log path was added, removed, or spelled past the discovery patterns"
fi

if list_is_distinct ${log_values[@]+"${log_values[@]}"}; then
    ok "all ${#log_values[@]} discovered log variables evaluate to distinct paths in one run"
else
    bad "the ${#log_values[@]} discovered log value(s) are not pairwise distinct in one run: two steps share a log, or the discovery found fewer than two"
fi

# --- the redirect/pipe targets, discovered by shape rather than by spelling ----
# The section above pins the *spelled* forms the current steps use; a target
# written as a fixed literal is invisible to it. This section is the invariant:
# every target word a run block redirects to or pipes into, whatever its
# spelling, must be per-run. The review's counterexample —
# `... 2>&1 | tee "$log" >> /tmp/shared.log` — is refused here on its literal.
guard_target_words=14
guard_target_exempt=52
target_words=()
target_values=()
exempt_items=0
block=0
while [ "$block" -lt "$guard_blocks" ]; do
    block=$((block + 1))
    body="$work/blocks/block-$block.body"
    if [ ! -f "$body" ]; then
        bad "run block $block has no parsed body (the block parser and the step counter disagree)"
        continue
    fi
    ctx="$work/blocks/block-$block.ctx"
    [ -f "$ctx" ] || block_context "$body" > "$ctx"
    seen="$work/blocks/block-$block.targets"
    : > "$seen"
    while IFS=$'\t' read -r op kind word; do
        [ -n "$word" ] || continue
        if [ "$kind" = "fddup" ]; then
            exempt_items=$((exempt_items + 1))
            continue
        fi
        first=$(eval_word_in_context "$ctx" "$word")
        second=$(eval_word_in_context "$ctx" "$word")
        if [ -z "$first" ]; then
            bad "the target $word in run block $block ($op) evaluates to nothing: its context or its spelling cannot produce a path"
            continue
        fi
        case "$first" in
            /dev/null|/dev/stdout|/dev/stderr|/dev/fd/*|-)
                exempt_items=$((exempt_items + 1))
                continue
                ;;
        esac
        if grep -Fxq -- "$word" "$seen" 2>/dev/null; then
            continue
        fi
        printf '%s\n' "$word" >> "$seen"
        target_words+=("$block:$op:$word")
        target_values+=("$first")
        if [ "$first" != "$second" ]; then
            ok "the target $word in run block $block ($op) is per-run (evaluated in its own context twice: $first)"
        else
            bad "the target $word in run block $block ($op) evaluates to the same path in two shells ($first): concurrent runs of this step would share it"
        fi
    done < <(block_target_items "$body")
done

if [ "${#target_words[@]}" = "$guard_target_words" ]; then
    ok "the job's $guard_blocks run blocks name $guard_target_words non-exempt target word(s), discovered by shape rather than by spelling"
else
    bad "the job's run blocks name ${#target_words[@]} non-exempt target word(s), not the pinned $guard_target_words (parsed $guard_blocks block(s)): a redirect target was added, removed, or spelled past the scanner"
fi

if [ "$exempt_items" = "$guard_target_exempt" ]; then
    ok "the scanner exempted $guard_target_exempt redirect item(s) as fd duplications and /dev sinks; no other exemption is recognised"
else
    bad "the scanner classified $exempt_items redirect item(s) as exempt, not the pinned $guard_target_exempt: the exemption set is only fd duplications and the /dev sinks, so this is a new exempt shape or a changed count"
fi

if list_is_distinct ${target_values[@]+"${target_values[@]}"}; then
    ok "all ${#target_values[@]} evaluated target paths are pairwise distinct in one run"
else
    bad "the ${#target_values[@]} evaluated target path(s) are not pairwise distinct in one run: two steps share a target, or the scanner found fewer than two"
fi

# --- every log path's parent must be a real directory --------------------------
# `log=/tmp/<per-run>.log/tmp/other.log` keeps a per-run component and 11 distinct
# tokens, but the real path's parent is a file: the redirect cannot succeed, the
# suite never runs, and the step's own `|| status=1` reds it. A path whose parent
# does not exist cannot be a log this job writes successfully, and no step here
# `mkdir`s its log's parent, so this is a true invariant.
parent_dir_exists() { [ -d "$(dirname -- "$1")" ]; }
parent_missing=''
parents_ok=1
for path in ${log_values[@]+"${log_values[@]}"}; do
    [ -n "$path" ] || continue
    if ! parent_dir_exists "$path"; then
        parents_ok=0
        parent_missing="$parent_missing $path (parent: $(dirname -- "$path"))"
    fi
done
if [ "$parents_ok" = "1" ]; then
    ok 'every evaluated log path sits in an existing parent directory'
else
    bad "these evaluated log paths have no existing parent directory:$parent_missing"
fi
target_parent_missing=''
target_parents_ok=1
for path in ${target_values[@]+"${target_values[@]}"}; do
    [ -n "$path" ] || continue
    if ! parent_dir_exists "$path"; then
        target_parents_ok=0
        target_parent_missing="$target_parent_missing $path (parent: $(dirname -- "$path"))"
    fi
done
if [ "$target_parents_ok" = "1" ]; then
    ok 'every evaluated target path sits in an existing parent directory'
else
    bad "these evaluated target paths have no existing parent directory:$target_parent_missing"
fi

# --- enforcer canaries --------------------------------------------------------
# The predicate above decides every live path, so a predicate that always says
# "fine" would pass this whole file. These four checks feed it known-answer
# inputs, including one that must be accepted.
if token_is_run_unique '/tmp/frp-canary.$$.log'; then
    ok 'canary: a path carrying \$\$ is accepted by the same predicate'
else
    bad 'canary: a path carrying \$\$ was refused (the predicate is too strict to trust)'
fi
if token_is_run_unique '/tmp/frp-canary.log'; then
    bad 'canary: a fixed path with no \$\$ was accepted (the predicate cannot detect the flake it exists for)'
else
    ok 'canary: a fixed path with no \$\$ is refused'
fi
if token_is_run_unique '/tmp/frp-canary-$HOME.log'; then
    bad 'canary: a path whose only $ is a variable expansion was accepted'
else
    ok 'canary: a path with a shell construct other than \$\$ is refused'
fi
if list_is_distinct '/tmp/frp-canary-a.$$.log' '/tmp/frp-canary-b.$$.log'; then
    ok 'canary: the distinctness check accepts two evaluated paths that differ'
else
    bad 'canary: the distinctness check refused two paths that differ'
fi
if list_is_distinct '/tmp/frp-canary.$$.log' '/tmp/frp-canary.$$.log'; then
    bad 'canary: the distinctness check accepted two identical templates (it compares the wrong thing)'
else
    ok 'canary: the distinctness check refuses two identical templates'
fi
if parent_dir_exists '/tmp/frp-canary.$$.log'; then
    ok 'canary: the parent-directory rule accepts a /tmp-rooted path (its parent exists)'
else
    bad 'canary: the parent-directory rule refused a /tmp-rooted path whose parent exists'
fi
if parent_dir_exists "$work/no-such-log-dir/canary.log"; then
    bad 'canary: the parent-directory rule accepted a path under a directory that does not exist'
else
    ok 'canary: the parent-directory rule refuses a path under a nonexistent directory'
fi
# The scanner decides every live target, so it carries known-answer inputs of its
# own: the review's recipe must be discovered (its literal included), a comment
# and a quoted case label must not be, and the per-run rule must refuse a literal
# while accepting a command substitution.
printf '%s\n' 'bash scripts/tests/rss-soak-run-dir.sh 2>&1 | tee "$log" >> /tmp/hff-canary-shared.log || status=1' > "$work/canary-recipe.sh"
canary_targets=0
canary_literal=0
while IFS=$'\t' read -r op kind word; do
    [ -n "$word" ] || continue
    if [ "$kind" = "fddup" ]; then
        continue
    fi
    canary_targets=$((canary_targets + 1))
    if [ "$word" = "/tmp/hff-canary-shared.log" ]; then
        canary_literal=1
    fi
done < <(block_target_items "$work/canary-recipe.sh")
if [ "$canary_targets" = "2" ] && [ "$canary_literal" = "1" ]; then
    ok 'canary: the scanner finds both the piped variable target and the appended literal target in the review recipe (2 non-fd items)'
else
    bad "canary: the scanner found $canary_targets non-fd item(s) in the review recipe (literal seen: $canary_literal); it must find 2, including the literal"
fi
printf '%s\n' '# > /tmp/hff-canary-comment.log' "case \$line in '  ok '*) : ;; '-> child red') : ;; esac" > "$work/canary-prose.sh"
canary_prose=$(block_target_items "$work/canary-prose.sh" | wc -l | tr -d ' ')
if [ "$canary_prose" = "0" ]; then
    ok 'canary: a commented redirect and a quoted case label carrying -> are not discovered as targets'
else
    bad "canary: the scanner discovered $canary_prose item(s) in a comment and a quoted case label; prose and comments are not redirects"
fi
: > "$work/canary-empty.ctx"
canary_lit_a=$(eval_word_in_context "$work/canary-empty.ctx" '/tmp/hff-canary-shared.log')
canary_lit_b=$(eval_word_in_context "$work/canary-empty.ctx" '/tmp/hff-canary-shared.log')
if [ -n "$canary_lit_a" ] && [ "$canary_lit_a" = "$canary_lit_b" ]; then
    ok 'canary: a literal target word evaluates identically in two shells, so the per-run rule refuses it'
else
    bad "canary: a literal target word did not evaluate identically twice ('$canary_lit_a' vs '$canary_lit_b'); the per-run rule would accept the review's counterexample"
fi
canary_sub_a=$(eval_word_in_context "$work/canary-empty.ctx" '"$(mktemp)"')
canary_sub_b=$(eval_word_in_context "$work/canary-empty.ctx" '"$(mktemp)"')
if [ -n "$canary_sub_a" ] && [ "$canary_sub_a" != "$canary_sub_b" ]; then
    ok 'canary: a command-substitution target word evaluates differently in two shells, so the per-run rule accepts it'
else
    bad "canary: a command-substitution target word did not evaluate differently twice ('$canary_sub_a' vs '$canary_sub_b'); the rule is too strict to trust"
fi

printf 'guard self-hash (sha256): %s\n' "$guard_self_sha"
printf '\nRESULT: %d fixture check(s) hold\n' "$((checks - fails))"
exit "$fails"
