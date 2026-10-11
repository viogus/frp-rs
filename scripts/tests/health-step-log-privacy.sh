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
# The shape it pins. Nine of the health job's thirteen fixture steps write their
# suite's output to one fixed path under /tmp and then judge that path:
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
#   * two concurrent full 13-step sweeps x 4 rounds: step 06 red in round 2, both
#     lanes; step 08 red in rounds 2 and 4. That is 4 red step-runs out of 8
#     lane-rounds (104 step-runs), with rounds 1 and 3 all green — a flake, not a
#     deterministic failure;
#   * step 6's body with the shipped path, two concurrent lanes: `status=1` with
#     `ok=108 result=1 fail=0 exact=269` (round 4) and `ok=232/237` (round 2) —
#     2 of 5 rounds; every other lane scored `ok=269 result=1 status=0`;
#   * the same body with only `.$$` inserted before the extension, same host,
#     same rounds, same contention: 0 reds in 10 lane-runs, every one of them
#     `ok=269 result=1 status=0`.
#
# The fix is therefore one token per path: make the path per-run. `$$` in a
# /tmp path is this repo's established idiom for exactly this (see
# scripts/tests/rss-soak-run-dir.sh, scripts/tests/inner-feature-port-probe.sh,
# scripts/remote-frps.sh).
#
# Why this is not a CI step: adding one would renumber every numeric
# `.github/workflows/ci.yml` citation that live files carry, which is the reason
# `scripts/tests/inner-feature-port-probe.sh` records for staying unwired. Run it
# by hand after touching the health job:
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
MIN_CHECKS=24
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

work=$(mktemp -d "${TMPDIR:-/tmp}/health-log-privacy.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap 'floor_check; cleanup; exit "$fails"' EXIT

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
    ok 'every /tmp/frp path is assigned exactly once (no copy-pasted path between two steps)'
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
    bad 'two of the health job paths evaluate to the same file in one run'
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

printf '\nRESULT: %d fixture check(s) hold\n' "$((checks - fails))"
exit "$fails"
