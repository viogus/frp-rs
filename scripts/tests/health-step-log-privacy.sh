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
#     `.$$`. The reproducible basis is the offset (staggered) launch: a truly
#     simultaneous launch did not red the shipped path in either rebuild (the
#     reviewer measured S 0/20 and F 0/20; the author's lockstep probe recorded
#     0/32), so that row is not part of this evidence.
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
#      targets, so a redirect written as a fixed literal is invisible to it.
#      Check 6 below is the property, and it does not depend on this spelling;
#   6. every redirect-like token in every run block — the invariant, and the
#      reason this file exists. The scanner below lexes each block with its
#      comments stripped and classifies *every* redirect operator it sees: a
#      `>`/`>>`/`>|`/`&>`/`&>>`/`N>`/`<>` yields an evaluated target word,
#      `<`/`N<` a source read, `>&`/`N>&` a file-descriptor duplication, and a
#      here-string/here-document word an explicit no-path exemption. It finds
#      targets by command position and by a two-phase reading of the command
#      word: a word it can read statically is matched against its watch list by
#      basename and by prefixer (a `tee` — `tee`, `sudo tee`, `command tee`,
#      `/usr/bin/tee`, `nice -n 5 tee`, `timeout 60 tee`, `setsid tee`,
#      `sudo -u nobody tee`, `xargs -I{} tee` — contributes *all* of its file
#      arguments after `--` and `-a`/`-i`/`-p`, a `dd` its `of=`, a `cat` its
#      arguments), and a word it cannot read (an escaped, half-escaped,
#      ANSI-quoted or command-substituted spelling: `\tee`, `te\e`, `$'\x74ee'`,
#      `$(echo tee)`, `"$(command -v tee)"`) is evaluated as a shell word in the
#      block's own leading-assignment context, in two separate shells, and if
#      both agree on a command basename the block is re-scanned with that name.
#      The scanner recurses into `$(...)`, backticks and process substitutions
#      (`>(...)`) and into the literal text of `eval` and `sh -c`, so a `tee`
#      inside a helper function body or a `cat > /tmp/x` inside a command text
#      is found; a shell keyword (`if`/`then`/`do`/`while`/`!`/…) does not end
#      command position, and a `case` pattern word is data until its `)` opens
#      the body. A quoted case label such as `'-> child red'` is a word, not a
#      redirect. Each non-exempt target word is then evaluated as a shell word
#      in the block's own leading-assignment context, in two separate shells,
#      and required to differ — so a fixed literal target
#      (`| tee "$log" >> /tmp/shared.log`, `dd of=/tmp/shared`,
#      `bash ... > /tmp/anything.log`) reds on its own, naming the block, the
#      target and both evaluated values, with `guard_region_pin` left at the
#      unmodified job's hash. These values are also required to be pairwise
#      distinct across all steps;
#   6b. the scanner refuses rather than ignores, which is what keeps 6 an
#      invariant instead of a list of known spellings. Every operator it lexed
#      must be accounted for by exactly one classification (the scanner prints
#      one `#accounting` line per block, and a mismatch is a red on its own),
#      and anything it cannot classify is a `refuse` item: an operator with no
#      target word, an unterminated quote or substitution, and an `eval`/`sh -c`
#      text that is not a literal. A refusal is a red run naming the block, the
#      ci.yml line and the text, so `helper() { tee /tmp/f.log; }; ... | helper`
#      is caught by the `tee` in command position, `eval "tee /tmp/f.log"` and
#      `sh -c 'cat > /tmp/f.log'` by scanning their literal text,
#      `bash -c 'cat "$0" >> /tmp/f.log' "$log"` likewise, and a redirect written
#      in a shape the scanner cannot read is refused rather than skipped;
#   6c. a command-position word the scanner cannot read is resolved, not
#      skipped. The block's own leading assignments are the context, and each
#      such word is evaluated in it in two separate shells: if both agree on a
#      command basename, the block is re-scanned with that name (so `\tee`,
#      `te\e`, `$'\x74ee'`, `$(echo tee)` and `"$(command -v tee)"` are all
#      `tee`, and a prelude `t=tee` makes `$t /tmp/f.log` a target); if the two
#      shells disagree the block reds with both values, because a command that
#      changes between runs cannot be accounted for; if both are empty and the
#      word is not a bare variable reference the block reds as a command that
#      cannot name anything; and a recognised prefixer's operands are walked so
#      that `nice -n 5 tee`, `timeout 60 tee`, `setsid tee`, `sudo -u nobody tee`
#      and `stdbuf -o L tee` are all read. Each block prints one `ok` with its
#      own counts (resolved, refused, unresolved, and the documented
#      bare-variable residual). The single carve-out is a word that is exactly a
#      bare variable reference the block's prelude leaves unset or empty — step 2
#      legitimately runs its candidate as `"$cand"`, a loop variable set later in
#      the body — which is counted and printed rather than silently accepted;
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
#      distinctness comparison, the parent-directory rule, the target scanner and
#      the command-word resolution — a discovered literal, a second `tee`
#      argument, a `tee` inside a helper function, an operator with no target
#      word refused, a well-formed redirect not refused, prose and quoted labels
#      not discovered, the five escaped/quoted/substituted spellings of a watch
#      command, a watch command behind each recognised prefixer's operands, a
#      watch command at the head of an `if`/`while` body, the same prefixer and
#      keyword shapes with a per-run variable still yielding the single word
#      `"$log"`, a command word the prelude assigns (`t=tee`), and the
#      bare-variable carve-out with one word it must accept (`"$cand"`) and one
#      it must refuse (`$(false)`) — each with one input it must accept and one
#      it must refuse.
#
# Exemptions are explicit and complete: an fd-duplication operator (`>&N`,
# `2>&1`, `&N`) has no path and is not a target; a here-string/here-document
# word is data, not a path; and a target whose evaluated value is `/dev/null`,
# `/dev/stdout`, `/dev/stderr`, `/dev/fd/*` or `-` is a sink, not a shared log.
# Nothing else is exempt, and quoting carries no privilege: it only stops the
# surrounding operator from being read as a redirect (`'-> child red'` is a
# word). An earlier revision discovered targets only by quoted-`"$var"`
# spelling, which left the review's `| tee "$log" >> /tmp/shared.log` recipe
# green with a genuinely shared fixed path; the operator-level scan is what
# closes that, and it is deliberately not implemented as a wider grep pattern or
# a wider exemption list.
#
# Residual limits, stated rather than implied — what this round closed and what
# it did not. Closed: a `tee` in a helper function, all of a `tee`'s arguments,
# `sudo`/`command`/path-qualified `tee`, `dd`/`cat` arguments, a `$(<file)` read,
# process substitution, any redirect operator the scanner cannot classify (now
# refused, not ignored), and a command word it cannot read (now resolved, not
# skipped): `\tee`, `te\e`, `$'\x74ee'`, `$(echo tee)`, `"$(command -v tee)"`, a
# `tee` reached through a prefixer's operands (`nice -n 5`, `timeout 60`,
# `setsid`, `sudo -u nobody`, `stdbuf -o L`, `xargs -I{}`), a `tee` at the head
# of an `if`/`while` body, and a command word the block's prelude assigns. What
# genuinely remains: an `eval`/`sh -c` text that is not a literal is refused, not
# executed, so a shared path hidden in a runtime-built command text reds as a
# refusal rather than being caught as a target; a watch command that is an
# argument of a plain wrapper this scanner does not treat as a prefixer is not a
# command position it recognises (measured: `find /tmp -exec tee /tmp/f.log \;`
# yields no target), as is a command named only through a variable the block's
# prelude does not set (`t=tee` written inside the body) — that one is the
# counted bare-variable residual, not a refusal, and a fixed path behind it would
# be invisible (measured: the live job's only two such words are `"$cand"` and
# `$guard_hasher`, neither of which writes a log); a shell reading its script
# from stdin is not scanned; a quoted word carrying `>` that is not a command
# text is a word, not a redirect (measured: no live line does this, and the live
# `"… <none> …"` line must stay green, so the trade is deliberate); and `set -x`
# trace output is not scanned. Each would need a new shape here, not a wider
# exemption list.
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
MIN_CHECKS=109
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

guard_region_pin=5f5b43ea66b6cd8fd177f8a18b46b672db59221dee9940fdfa2da17611019f8e
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
# Each body line's region line number is recorded alongside it, so a refusal can
# name the ci.yml line rather than an offset inside the block.
awk -v dir="$work/blocks" '
    function close_block() { if (open_) { close(f); close(m); open_ = 0 } }
    /^[[:space:]]+run:/ {
        close_block()
        match($0, /^[ ]+/); ind = RLENGTH
        n++
        f = dir "/block-" n ".body"
        m = dir "/block-" n ".map"
        open_ = 1
        run_ind = ind
        rest = substr($0, ind + 1)
        sub(/^run:[[:space:]]*/, "", rest)
        if (rest != "" && rest != "|" && rest != "|-" && rest != "|+" && rest != ">" && rest != ">-") {
            print "# inline run: " rest > f
            print NR > m
        }
        next
    }
    open_ {
        if ($0 ~ /^[[:space:]]*$/) { print "" > f; print NR > m; next }
        match($0, /^[ ]*/); ind2 = RLENGTH
        if (ind2 > run_ind) { print substr($0, run_ind + 3) > f; print NR > m; next }
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
# A command word that is exactly a variable reference the block's leading
# assignments leave unset or empty names a command this guard cannot resolve
# (step 2 runs its candidate as `"$cand"`, a loop variable set later in the
# body). That is the documented residual, not a shape to refuse -- and an
# assignment *in the prelude* is different: `t=tee` in the prelude makes a later
# `$t /tmp/f.log` resolve to `tee` and be caught like any other target.
is_bare_var_ref() {
    local w="$1"
    case "$w" in '"'*'"') w="${w:1:${#w}-2}" ;; esac
    [[ "$w" =~ ^\$\{[A-Za-z_][A-Za-z0-9_]*\}$ ]] && return 0
    [[ "$w" =~ ^\$[A-Za-z_][A-Za-z0-9_]*$ ]] && return 0
    [[ "$w" =~ ^\$[0-9@*#?$!-]$ ]] && return 0
    return 1
}

# The redirect/pipe target scanner. Discovery by *shape*, not by spelling: this
# is the check an earlier quoted-`"$var"`-only grep could not make, and it has
# two duties. First, read every redirect-like construct out of a block whatever
# its spelling: `>`/`>>`/`>|`/`&>`/`&>>`/`N>` targets, every `tee` file argument,
# every `dd of=`, a process substitution (whose body is scanned recursively), a
# redirect inside `$(...)`/backticks/`eval`/`sh -c`, and the read side
# (`$(<file)`, `cat <file>`, `<`). Second, refuse rather than ignore: every
# redirect operator lexed must end up either classified or refused, and a
# redirect whose target cannot be read (an operator with no word, an
# unterminated quote/substitution, or an `eval`/`-c` text that is not a literal)
# is refused with the block line and the text. Output is one
# `op<TAB>kind<TAB>word<TAB>line` line per item and one
# `#accounting<TAB>lexed<TAB>class<TAB>refused` line per block; the caller
# re-checks that lexed == class + refused, so a construct the scanner neither
# classified nor refused fails the guard instead of disappearing. kind is
# `target` (a redirect or pipe target), `read` (a source read), `fddup` (an fd
# duplication naming no path), `exempt` (a here-document/here-string word or a
# process substitution) or `refuse`. Exemptions are decided by the caller
# (operator for `fddup`, evaluated value for the `/dev` sinks and `-`), never by
# this scanner.
block_target_items() {
    python3 -B - "$1" "${2:-}" <<'PY'
import re
import sys

PREFIX = {
    "sudo", "command", "env", "nohup", "time", "nice", "stdbuf", "xargs",
    "exec", "builtin", "doas", "timeout", "setsid", "ionice", "chrt",
    "taskset", "flock", "chroot", "unbuffer", "script",
}
# Shell keywords that start a command list rather than name a command. Without
# them `if`/`then`/`do` would end command position and the first real command of
# the branch (`if true; then tee ...; fi`) would be skipped.
KEYWORDS = {
    "if", "then", "else", "elif", "fi", "do", "done", "while", "until",
    "for", "in", "case", "esac", "!",
}
# A word the scanner can read as a command name without the block's context: a
# plain literal such as `tee`, `sh`, `/usr/bin/tee`. Anything else -- a quoted
# or escaped spelling, `$(...)`, a backtick, a variable -- is *opaque* and is
# handed to the caller, which resolves it in the block's own context in two
# shells and tells the scanner what it found.
PLAIN_RE = re.compile(r"^[A-Za-z0-9_./+:\-\[\]]+$")
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "mksh"}
WATCH = {"tee", "dd", "eval"}
READ_CMDS = {"cat"}
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
OP_RE = re.compile(r"[0-9]*(?:&>>|&>|>>|>\||>&|<\||<>|<<-|<<<|<<|>|<)")
FD_DUP_RE = re.compile(r"^-$|^[0-9]+$")


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


def norm_word(raw):
    """The one spelling of a word that the scanner and the caller both use.

    The scanner reports one line per item and the shell joins a backslash
    continuation, so both sides normalise before comparing.
    """
    return " ".join(raw.replace("\\\n", "").split())


class Tok(object):
    __slots__ = ("kind", "raw", "simple", "line")

    def __init__(self, kind, raw="", simple="", line=0):
        self.kind = kind
        self.raw = raw
        self.simple = simple
        self.line = line


class Scanner(object):
    def __init__(self, overrides=None):
        self.items = []
        self.refusals = []
        self.cmds = []
        self.overrides = overrides or {}
        self.stats = {"lexed": 0, "class": 0, "refused": 0, "nested": 0}

    def refuse(self, line, text, why):
        self.refusals.append((line, text, why))

    def refuse_op(self, line, text, why):
        self.stats["refused"] += 1
        self.refusals.append((line, text, why))

    def add(self, op, kind, word, line):
        word = " ".join(str(word).split())
        self.items.append((op, kind, word, line))

    def find_close(self, code, i):
        """code[i] == '('; return the index just past the matching ')'."""
        n = len(code)
        depth = 0
        quote = None
        j = i
        while j < n:
            c = code[j]
            if quote:
                if quote == '"' and c == "\\":
                    j += 2
                    continue
                if c == quote:
                    quote = None
                j += 1
                continue
            if c == "\\":
                j += 2
                continue
            if c in ("'", '"'):
                quote = c
                j += 1
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return -1

    def find_brace(self, code, i):
        """code[i] == '{'; return the index just past the matching '}'."""
        n = len(code)
        depth = 0
        quote = None
        j = i
        while j < n:
            c = code[j]
            if quote:
                if quote == '"' and c == "\\":
                    j += 2
                    continue
                if c == quote:
                    quote = None
                j += 1
                continue
            if c == "\\":
                j += 2
                continue
            if c in ("'", '"'):
                quote = c
                j += 1
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return -1

    def find_backtick(self, code, i):
        n = len(code)
        j = i + 1
        while j < n:
            if code[j] == "\\":
                j += 2
                continue
            if code[j] == "`":
                return j + 1
            j += 1
        return -1

    def scan_text(self, text, depth=0, base_line=0):
        """Lex a whole block: comments are stripped per line, everything else is
        one stream, so a construct split by a line continuation still closes."""
        code = "\n".join(strip_comment(l) for l in text.split("\n"))
        toks = self.lex(code, base_line + 1, depth)
        self.walk(toks, depth)

    def lex(self, code, lineno, depth):
        toks = []
        i, n = 0, len(code)
        while i < n:
            c = code[i]
            if c == "\n":
                toks.append(Tok("sep", "\n", "\n", lineno))
                lineno += 1
                i += 1
                continue
            if c in " \t":
                i += 1
                continue
            if c == "\\" and i + 1 < n and code[i + 1] == "\n":
                lineno += 1
                i += 2
                continue
            if code.startswith(";;", i):
                toks.append(Tok("sep", ";;", line=lineno))
                i += 2
                continue
            if code.startswith("&&", i) or code.startswith("||", i):
                toks.append(Tok("sep", code[i:i + 2], line=lineno))
                i += 2
                continue
            if c in ("<", ">") and i + 1 < n and code[i + 1] == "(":
                end = self.find_close(code, i + 1)
                if end < 0:
                    self.refuse(lineno, code[i:i + 20],
                                "an unterminated process substitution")
                    i = n
                    continue
                toks.append(Tok("procsub", code[i:end], code[i:end], lineno))
                self.stats["nested"] += 1
                self.scan_text(code[i + 2:end - 1], depth + 1, lineno - 1)
                i = end
                continue
            m = OP_RE.match(code, i)
            if m:
                op = m.group(0)
                toks.append(Tok("op", op, op, lineno))
                self.stats["lexed"] += 1
                i += len(op)
                continue
            if c in ";|&(){}":
                toks.append(Tok("sep", c, c, lineno))
                i += 1
                continue
            tok, i, lineno = self.read_word(code, i, lineno, depth)
            if tok is not None:
                toks.append(tok)
        return toks

    def read_word(self, code, i, lineno, depth):
        n = len(code)
        raw = []
        simple = []
        quote = None
        while i < n:
            c = code[i]
            if quote is None:
                if c == "\\" and i + 1 < n and code[i + 1] == "\n":
                    lineno += 1
                    i += 2
                    continue
                if c in " \t\n":
                    break
                if c in ";|&<>()":
                    break
                if c == "\\":
                    raw.append(c)
                    simple.append(c)
                    i += 1
                    if i < n:
                        raw.append(code[i])
                        simple.append(code[i])
                        if code[i] == "\n":
                            lineno += 1
                        i += 1
                    continue
                if c in ("'", '"'):
                    quote = c
                    raw.append(c)
                    i += 1
                    continue
                if c == "`":
                    end = self.find_backtick(code, i)
                    if end < 0:
                        self.refuse(lineno, code[i:i + 20],
                                    "an unterminated backtick command substitution")
                        i = n
                        break
                    raw.append(code[i:end])
                    simple.append(code[i:end])
                    self.stats["nested"] += 1
                    self.scan_text(code[i + 1:end - 1], depth + 1, lineno - 1)
                    lineno += code[i:end].count("\n")
                    i = end
                    continue
                if code.startswith("$((", i):
                    end = self.find_close(code, i + 1)
                    if end < 0:
                        self.refuse(lineno, code[i:i + 20],
                                    "an unterminated arithmetic expansion")
                        i = n
                        break
                    raw.append(code[i:end])
                    simple.append(code[i:end])
                    lineno += code[i:end].count("\n")
                    i = end
                    continue
                if code.startswith("${", i):
                    end = self.find_brace(code, i + 1)
                    if end < 0:
                        self.refuse(lineno, code[i:i + 20],
                                    "an unterminated parameter expansion")
                        i = n
                        break
                    raw.append(code[i:end])
                    simple.append(code[i:end])
                    lineno += code[i:end].count("\n")
                    i = end
                    continue
                if code.startswith("$(", i):
                    end = self.find_close(code, i + 1)
                    if end < 0:
                        self.refuse(lineno, code[i:i + 20],
                                    "an unterminated command substitution")
                        i = n
                        break
                    raw.append(code[i:end])
                    simple.append(code[i:end])
                    self.stats["nested"] += 1
                    self.scan_text(code[i + 2:end - 1], depth + 1, lineno - 1)
                    lineno += code[i:end].count("\n")
                    i = end
                    continue
                raw.append(c)
                simple.append(c)
                i += 1
                continue
            if c == "\\" and quote == '"':
                raw.append(c)
                simple.append(c)
                i += 1
                if i < n:
                    raw.append(code[i])
                    simple.append(code[i])
                    if code[i] == "\n":
                        lineno += 1
                    i += 1
                continue
            if quote == '"' and c == "`":
                end = self.find_backtick(code, i)
                if end < 0:
                    self.refuse(lineno, code[i:i + 20],
                                "an unterminated backtick command substitution")
                    i = n
                    break
                raw.append(code[i:end])
                simple.append(code[i:end])
                self.stats["nested"] += 1
                self.scan_text(code[i + 1:end - 1], depth + 1, lineno - 1)
                lineno += code[i:end].count("\n")
                i = end
                continue
            if quote == '"' and code.startswith("$((", i):
                end = self.find_close(code, i + 1)
                if end < 0:
                    self.refuse(lineno, code[i:i + 20],
                                "an unterminated arithmetic expansion")
                    i = n
                    break
                raw.append(code[i:end])
                simple.append(code[i:end])
                lineno += code[i:end].count("\n")
                i = end
                continue
            if quote == '"' and code.startswith("${", i):
                end = self.find_brace(code, i + 1)
                if end < 0:
                    self.refuse(lineno, code[i:i + 20],
                                "an unterminated parameter expansion")
                    i = n
                    break
                raw.append(code[i:end])
                simple.append(code[i:end])
                lineno += code[i:end].count("\n")
                i = end
                continue
            if quote == '"' and code.startswith("$(", i):
                end = self.find_close(code, i + 1)
                if end < 0:
                    self.refuse(lineno, code[i:i + 20],
                                "an unterminated command substitution")
                    i = n
                    break
                raw.append(code[i:end])
                simple.append(code[i:end])
                self.stats["nested"] += 1
                self.scan_text(code[i + 2:end - 1], depth + 1, lineno - 1)
                lineno += code[i:end].count("\n")
                i = end
                continue
            if c == quote:
                quote = None
                raw.append(c)
                i += 1
                continue
            if c == "\n":
                lineno += 1
            raw.append(c)
            simple.append(c)
            i += 1
        if quote is not None:
            self.refuse(lineno, "".join(raw) + code[i:i + 20],
                        "an unterminated %s quote: the rest of the block cannot be classified"
                        % ("single" if quote == "'" else "double"))
            while i < n:
                if code[i] == "\n":
                    lineno += 1
                raw.append(code[i])
                i += 1
        if not raw:
            return None, i, lineno
        return Tok("word", "".join(raw), "".join(simple), lineno), i, lineno

    def walk(self, toks, depth):
        cmdpos = True
        pending = False     # inside a recognised prefixer's operand list
        case_state = None   # None | "pattern" | "body"
        k = 0
        while k < len(toks):
            t = toks[k]
            if t.kind == "sep":
                pending = False
                if case_state == "pattern":
                    # `)` opens the branch body; anything else (newline, `|`)
                    # is still the pattern list, never a command word
                    if t.raw == ")":
                        case_state = "body"
                        cmdpos = True
                    else:
                        cmdpos = False
                elif case_state == "body" and t.raw in (";;", ";&", ";;&"):
                    case_state = "pattern"
                    cmdpos = False
                else:
                    cmdpos = True
                k += 1
                continue
            if t.kind == "op":
                nxt = toks[k + 1] if k + 1 < len(toks) else None
                if nxt is None or nxt.kind in ("op", "sep"):
                    self.refuse_op(t.line, t.raw,
                                   "the redirect operator %s has no target word" % t.raw)
                    k += 1
                    continue
                self.classify_op(t, nxt)
                k += 2
                continue
            if t.kind == "procsub":
                k += 1
                continue
            if case_state is not None and t.simple == "esac":
                case_state = None
                cmdpos = False
                pending = False
                k += 1
                continue
            if case_state == "pattern":
                k += 1
                continue
            if not cmdpos:
                k += 1
                continue
            s = t.simple
            if s in KEYWORDS:
                if s == "case":
                    case_state = "pattern"
                    cmdpos = False
                else:
                    cmdpos = True
                pending = False
                k += 1
                continue
            if s.startswith("-"):
                k += 1
                continue
            if ASSIGN_RE.match(s):
                k += 1
                continue
            key = norm_word(t.raw)
            mapped = self.overrides.get(key)
            if mapped is not None:
                base = mapped
            else:
                base = s.split("/")[-1]
                if not PLAIN_RE.match(key) or t.raw != t.simple:
                    # opaque: the caller resolves it in the block's own context
                    self.cmds.append((key, t.line))
            if base in PREFIX:
                pending = True
                cmdpos = True
                k += 1
                continue
            if base in WATCH or base in SHELLS or base in READ_CMDS:
                k = self.handle_command(base, toks, k, depth)
                cmdpos = False
                pending = False
                continue
            if pending:
                # an operand of a recognised prefixer, not the command word
                k += 1
                continue
            cmdpos = False
            k += 1

    def args_from(self, toks, k):
        j = k + 1
        args = []
        while j < len(toks) and toks[j].kind not in ("sep", "op"):
            if toks[j].kind == "word":
                args.append(toks[j])
            j += 1
        return args, j

    def handle_command(self, base, toks, k, depth):
        args, j = self.args_from(toks, k)
        if base == "tee":
            for a in args:
                if a.simple.startswith("-"):
                    continue
                self.add("tee", "target", a.raw, a.line)
            return j
        if base == "dd":
            for a in args:
                if a.simple.startswith("of=") and len(a.simple) > 3:
                    pos = a.raw.find("of=")
                    self.add("dd-of", "target", a.raw[pos + 3:], a.line)
            return j
        if base in READ_CMDS:
            for a in args:
                if a.simple.startswith("-"):
                    continue
                self.add(base, "read", a.raw, a.line)
            return j
        if base == "eval":
            for a in args:
                self.defer_or_scan(a, depth)
            return j
        ci = None
        for idx, a in enumerate(args):
            if a.simple == "-c" or (a.simple.startswith("-") and "c" in a.simple[1:]
                                    and not a.simple.startswith("--")):
                ci = idx
                break
        if ci is not None and ci + 1 < len(args):
            self.defer_or_scan(args[ci + 1], depth)
        return j

    def defer_or_scan(self, tok, depth):
        """A command-position text (an `eval` argument, a shell `-c` string) must
        be accounted for, not ignored: scan the literal, refuse when it is not one."""
        before = len(self.items) + len(self.refusals)
        text = tok.simple
        self.stats["nested"] += 1
        self.scan_text(text, depth + 1, tok.line - 1)
        if len(self.items) + len(self.refusals) > before:
            return
        if "$" in text or "`" in text:
            self.refuse(tok.line, tok.raw,
                        "the command text is not a literal the scanner can read (it carries "
                        "an expansion), so any redirect it performs is invisible here: %s"
                        % text[:80])
        else:
            self.refuse(tok.line, tok.raw,
                        "the command text %r names no redirect the scanner can classify"
                        % text[:60])

    def classify_op(self, op, tgt):
        o = op.raw
        self.stats["class"] += 1
        if tgt.kind == "procsub":
            self.add(o, "exempt",
                     "a process substitution, whose body the scanner scanned", op.line)
            return
        if o.endswith(">&") or o.endswith("<&"):
            if FD_DUP_RE.match(tgt.simple):
                self.add(o, "fddup", tgt.raw, op.line)
            else:
                self.add(o, "target", tgt.raw, op.line)
            return
        if o.endswith("<<<") or o.endswith("<<") or o.endswith("<<-"):
            self.add(o, "exempt",
                     "a here-document/here-string word, not a path: %s" % tgt.raw, op.line)
            return
        if o.endswith("<>"):
            self.add(o, "target", tgt.raw, op.line)
            return
        if o.endswith("<"):
            self.add(o, "read", tgt.raw, op.line)
            return
        self.add(o, "target", tgt.raw, op.line)


overrides = {}
if len(sys.argv) > 2 and sys.argv[2]:
    with open(sys.argv[2], errors="replace") as fh:
        for ln in fh:
            parts = ln.rstrip("\n").split("\t")
            if len(parts) == 2 and parts[0]:
                overrides[parts[0]] = parts[1]
with open(sys.argv[1], errors="replace") as fh:
    sc = Scanner(overrides)
    sc.scan_text(fh.read())
for op, kind, word, line in sc.items:
    sys.stdout.write("%s\t%s\t%s\t%d\n" % (op, kind, word, line))
for word, line in sc.cmds:
    sys.stdout.write("cmd\tcmd\t%s\t%d\n" % (word, line))
for line, text, why in sc.refusals:
    sys.stdout.write("refuse\trefuse\t%s\t%d\n"
                     % (" ".join(("%s (%s)" % (text, why)).split()), line))
sys.stdout.write("#accounting\t%d\t%d\t%d\n"
                 % (sc.stats["lexed"], sc.stats["class"], sc.stats["refused"]))
if sc.stats["lexed"] != sc.stats["class"] + sc.stats["refused"]:
    sys.stderr.write("scanner accounting failed: lexed=%d class=%d refused=%d\n"
                     % (sc.stats["lexed"], sc.stats["class"], sc.stats["refused"]))
    sys.exit(3)
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
# spelling, must be per-run, and every redirect-like construct the scanner
# cannot read must be refused here rather than skipped. The review's
# counterexample — `... 2>&1 | tee "$log" >> /tmp/shared.log` — is refused on
# its literal; a helper function's `tee`, an `eval`/`sh -c` text, a process
# substitution, an operator with no target word and an unterminated quote are
# refused by the scanner itself, naming the block, the ci.yml line and the text.
guard_target_words=14
guard_target_exempt=65
guard_target_reads=14
# A body line is not a ci.yml line: the block parser records the region line each
# body line came from, and the region starts at `region_start`.
yml_line_of() {
    local n
    n=$(sed -n "${2}p" "$work/blocks/block-$1.map" 2>/dev/null)
    [ -n "$n" ] || n="$2"
    printf '%s' "$((region_start + n - 1))"
}
scanner_refusals=0
refusal_text=''
accounting_blocks=0
target_words=()
target_values=()
exempt_items=0
read_items=0
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
    seen_reads="$work/blocks/block-$block.reads"
    : > "$seen"
    : > "$seen_reads"
    accounted=0
    # --- the command words the scanner could not name by itself ---------------
    # The scanner reports every command-position word it cannot read as a plain
    # literal -- an escaped or quoted spelling, `$(...)`, a backtick, a variable --
    # and this is where those words are resolved: in the block's own context, in
    # two separate shells, exactly like a target word. The result goes back to the
    # scanner so the same walk can classify what the command is (a `tee`, a `dd`,
    # an `eval`, a shell `-c`). Refusing outright would red step 2, which
    # legitimately runs `"$cand"`; *skipping* is what let `\tee` and
    # `$(echo tee)` write a shared fixed log while the guard stayed green.
    overrides="$work/blocks/block-$block.overrides"
    cmd_list="$work/blocks/block-$block.cmds"
    items="$work/blocks/block-$block.items"
    : > "$overrides"
    cmd_words=0
    cmd_resolved=0
    cmd_residual=0
    cmd_unresolved=0
    block_target_items "$body" > "$items"
    awk -F'\t' '$1 == "cmd" && $3 != "" && !seen[$3]++ { print $3 "\t" $4 }' "$items" > "$cmd_list"
    while IFS=$'\t' read -r cword cline; do
        [ -n "$cword" ] || continue
        cfirst=$(eval_word_in_context "$ctx" "$cword")
        csecond=$(eval_word_in_context "$ctx" "$cword")
        cmd_words=$((cmd_words + 1))
        if [ "$cfirst" != "$csecond" ]; then
            cmd_unresolved=$((cmd_unresolved + 1))
            bad "the command word $cword in run block $block (ci.yml:$(yml_line_of "$block" "$cline")) resolves differently in two shells ('$cfirst' vs '$csecond'): the scanner cannot account for a command that changes between runs"
            continue
        fi
        if [ -z "$cfirst" ]; then
            if is_bare_var_ref "$cword"; then
                cmd_residual=$((cmd_residual + 1))
                continue
            fi
            cmd_unresolved=$((cmd_unresolved + 1))
            bad "the command word $cword in run block $block (ci.yml:$(yml_line_of "$block" "$cline")) resolves to nothing: its context or its spelling cannot name a command, so a write through it would be invisible"
            continue
        fi
        cmd_resolved=$((cmd_resolved + 1))
        printf '%s\t%s\n' "$cword" "${cfirst##*/}" >> "$overrides"
    done < "$cmd_list"
    # Re-scan the same block with the resolved command names. Without this the
    # resolution above would only be reported, never applied: `\tee /tmp/f.log`
    # would still contribute no target, and the fixed path would stay invisible.
    if [ -s "$overrides" ]; then
        block_target_items "$body" "$overrides" > "$items"
    fi
    if [ "$cmd_unresolved" = "0" ]; then
        ok "run block $block accounted for $cmd_words opaque command word(s) in the block's own context in two shells: $cmd_resolved resolved to a command, $cmd_residual a bare variable reference the prelude leaves unset or empty (the documented residual), 0 unresolved"
    fi
    while IFS=$'\t' read -r op kind word bline; do
        if [ "$op" = "cmd" ]; then
            continue
        fi
        if [ "$op" = "#accounting" ]; then
            accounted=1
            accounting_blocks=$((accounting_blocks + 1))
            if [ "$kind" != "$((word + bline))" ]; then
                bad "run block $block: the scanner lexed $kind redirect operator(s) but accounted for $((word + bline)) of them (classified $word, refused $bline): an operator was neither classified nor refused"
            fi
            continue
        fi
        if [ "$op" = "refuse" ]; then
            scanner_refusals=$((scanner_refusals + 1))
            refusal_text="$refusal_text block $block at ci.yml:$(yml_line_of "$block" "$bline") ($word);"
            continue
        fi
        if [ "$kind" = "fddup" ] || [ "$kind" = "exempt" ]; then
            exempt_items=$((exempt_items + 1))
            continue
        fi
        if [ "$kind" = "read" ]; then
            if ! grep -Fxq -- "$word" "$seen_reads" 2>/dev/null; then
                printf '%s\n' "$word" >> "$seen_reads"
                read_items=$((read_items + 1))
            fi
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
    done < "$items"
    if [ "$accounted" != "1" ]; then
        bad "run block $block produced no scanner accounting line: the redirect scanner did not run on it or crashed, so no redirect in that block was classified"
    fi
done

if [ "$accounting_blocks" = "$guard_blocks" ]; then
    ok "every one of the $guard_blocks run blocks lexed its redirect operators and accounted for each one (classified or refused)"
else
    bad "only $accounting_blocks of $guard_blocks run block(s) produced a scanner accounting line: the redirect scanner did not run on the others"
fi

if [ "$scanner_refusals" = "0" ]; then
    ok 'the scanner refused no redirect-like construct in the unmodified job'
else
    bad "the scanner refused $scanner_refusals redirect-like construct(s) it could not classify:$refusal_text"
fi

if [ "${#target_words[@]}" = "$guard_target_words" ]; then
    ok "the job's $guard_blocks run blocks name $guard_target_words non-exempt target word(s), discovered by shape rather than by spelling"
else
    bad "the job's run blocks name ${#target_words[@]} non-exempt target word(s), not the pinned $guard_target_words (parsed $guard_blocks block(s)): a redirect target was added, removed, or spelled past the scanner"
fi

if [ "$exempt_items" = "$guard_target_exempt" ]; then
    ok "the scanner exempted $guard_target_exempt redirect item(s) as fd duplications, here-string/here-document words and /dev sinks; no other exemption is recognised"
else
    bad "the scanner classified $exempt_items redirect item(s) as exempt, not the pinned $guard_target_exempt: the exemption set is only fd duplications, here-string/here-document words and the /dev sinks, so this is a new exempt shape or a changed count"
fi

if [ "$read_items" = "$guard_target_reads" ]; then
    ok "the scanner found $guard_target_reads distinct source-read word(s) (\$(<file), cat <file>, <); a read target is not required to be per-run"
else
    bad "the scanner found $read_items distinct source-read word(s), not the pinned $guard_target_reads: a read was added, removed, or spelled past the scanner"
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
# own: the review's recipe must be discovered (its literal included), the second
# file argument of a `tee` pipeline and a `tee` inside a helper function must be
# discovered, a comment and a quoted case label must not be, an operator with no
# target word must be refused while a well-formed redirect must not be, and the
# per-run rule must refuse a literal while accepting a command substitution.
scanner_finds_literal() {
    block_target_items "$1" | awk -F'\t' -v want="$2" '
        $1 != "#accounting" && $1 != "refuse" && $3 == want { found = 1 }
        END { exit !found }'
}
scanner_refuses_op() {
    block_target_items "$1" | awk -F'\t' '$1 == "refuse" { found = 1 } END { exit !found }'
}
printf '%s\n' 'bash scripts/tests/rss-soak-run-dir.sh 2>&1 | tee "$log" >> /tmp/hff-canary-shared.log || status=1' > "$work/canary-recipe.sh"
canary_targets=0
canary_literal=0
while IFS=$'\t' read -r op kind word bline; do
    [ "$op" = "#accounting" ] && continue
    [ "$kind" = "fddup" ] && continue
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
printf '%s\n' 'bash scripts/tests/rss-soak-run-dir.sh 2>&1 | tee "$log" /tmp/hff-canary-tee-fixed.log || status=1' > "$work/canary-tee-multi.sh"
if scanner_finds_literal "$work/canary-tee-multi.sh" '/tmp/hff-canary-tee-fixed.log'; then
    ok 'canary: the scanner discovers the second file argument of a tee pipeline (tee "$log" /tmp/fixed.log)'
else
    bad "canary: the scanner missed the second file argument of a tee pipeline, so a fixed path passed to a tee argument past the first would be ignored"
fi
printf '%s\n' 'helper() { tee /tmp/hff-canary-helper.log; }' 'bash scripts/tests/rss-soak-run-dir.sh | helper' > "$work/canary-helper.sh"
if scanner_finds_literal "$work/canary-helper.sh" '/tmp/hff-canary-helper.log'; then
    ok 'canary: the scanner discovers a tee inside a helper function body that the pipeline calls'
else
    bad 'canary: the scanner missed a tee inside a helper function body, so a fixed path a helper writes would be ignored'
fi
printf '%s\n' 'bash scripts/tests/rss-soak-run-dir.sh >' > "$work/canary-refuse.sh"
if scanner_refuses_op "$work/canary-refuse.sh"; then
    ok 'canary: the scanner refuses a redirect operator with no target word instead of ignoring it'
else
    bad 'canary: the scanner ignored a redirect operator with no target word; a shape it cannot classify must be refused, not skipped'
fi
printf '%s\n' 'log=/tmp/frp-canary.$$.log' 'bash scripts/tests/rss-soak-run-dir.sh > "$log" 2>&1 || status=1' > "$work/canary-clean.sh"
if scanner_refuses_op "$work/canary-clean.sh"; then
    bad 'canary: the scanner refused a well-formed per-run redirect (the refusal rule is too strict to trust)'
else
    ok 'canary: the scanner does not refuse a well-formed per-run redirect'
fi
printf '%s\n' '# > /tmp/hff-canary-comment.log' "case \$line in '  ok '*) : ;; '-> child red') : ;; esac" > "$work/canary-prose.sh"
canary_prose=$(block_target_items "$work/canary-prose.sh" | grep -cv '^#accounting')
if [ "$canary_prose" = "0" ]; then
    ok 'canary: a commented redirect and a quoted case label carrying -> are not discovered as targets'
else
    bad "canary: the scanner discovered $canary_prose item(s) in a comment and a quoted case label; prose and comments are not redirects"
fi
: > "$work/canary-empty.ctx"
# The command words the scanner cannot read by itself are resolved by the caller,
# so these canaries exercise the same two-phase path: resolve the file's opaque
# command words in the given context, then ask the scanner again with those
# overrides. Without this a canary for `\tee` would only prove the scanner
# skipped it -- which is the defect this check exists for.
scanner_items_resolved() {
    local items="$work/canary-items.tsv" ov="$work/canary-overrides.tsv"
    local cword cfirst csecond
    : > "$ov"
    block_target_items "$1" > "$items"
    while IFS=$'\t' read -r cword cline; do
        [ -n "$cword" ] || continue
        cfirst=$(eval_word_in_context "$2" "$cword")
        csecond=$(eval_word_in_context "$2" "$cword")
        if [ -n "$cfirst" ] && [ "$cfirst" = "$csecond" ]; then
            printf '%s\t%s\n' "$cword" "${cfirst##*/}" >> "$ov"
        fi
    done < <(awk -F'\t' '$1 == "cmd" && $3 != "" && !seen[$3]++ { print $3 "\t" $4 }' "$items")
    block_target_items "$1" "$ov"
}
canary_all_found() {
    local file="$1" ctx="$2" lit
    shift 2
    for lit in "$@"; do
        if ! scanner_items_resolved "$file" "$ctx" | awk -F'\t' -v want="$lit" '
            $1 != "#accounting" && $1 != "refuse" && $3 == want { found = 1 }
            END { exit !found }'; then
            return 1
        fi
    done
    return 0
}
cat > "$work/canary-spellings.sh" <<'CANARY'
\tee /tmp/hff-canary-esc.log
te\e /tmp/hff-canary-halfesc.log
$'\x74ee' /tmp/hff-canary-ansi.log
$(echo tee) /tmp/hff-canary-subst.log
"$(command -v tee)" /tmp/hff-canary-path.log
CANARY
if canary_all_found "$work/canary-spellings.sh" "$work/canary-empty.ctx" \
        /tmp/hff-canary-esc.log /tmp/hff-canary-halfesc.log /tmp/hff-canary-ansi.log \
        /tmp/hff-canary-subst.log /tmp/hff-canary-path.log; then
    ok 'canary: an escaped, half-escaped, ANSI-quoted, command-substituted and resolved-path spelling of a watch command all resolve to it, so its fixed file argument is found'
else
    bad 'canary: the scanner missed a fixed file argument behind an escaped, quoted or substituted spelling of tee; a write through that spelling would be invisible'
fi
cat > "$work/canary-prefixers.sh" <<'CANARY'
nice -n 5 tee /tmp/hff-canary-nice.log
timeout 60 tee /tmp/hff-canary-timeout60.log
setsid tee /tmp/hff-canary-setsid.log
sudo -u nobody tee /tmp/hff-canary-sudo.log
stdbuf -o L tee /tmp/hff-canary-stdbuf.log
timeout 5 tee /tmp/hff-canary-timeout5.log
sudo -u root tee /tmp/hff-canary-sudoroot.log
CANARY
if canary_all_found "$work/canary-prefixers.sh" "$work/canary-empty.ctx" \
        /tmp/hff-canary-nice.log /tmp/hff-canary-timeout60.log /tmp/hff-canary-setsid.log \
        /tmp/hff-canary-sudo.log /tmp/hff-canary-stdbuf.log /tmp/hff-canary-timeout5.log \
        /tmp/hff-canary-sudoroot.log; then
    ok 'canary: a watch command reached through a prefixer and its operands (nice -n 5, timeout 60, setsid, sudo -u X, stdbuf -o L) is found, so its fixed file argument is not ignored'
else
    bad 'canary: the scanner missed a watch command behind a prefixer operand, so a fixed path passed that way would be ignored'
fi
cat > "$work/canary-keywords.sh" <<'CANARY'
if true; then tee /tmp/hff-canary-then.log; fi
while :; do tee /tmp/hff-canary-do.log; break; done
CANARY
if canary_all_found "$work/canary-keywords.sh" "$work/canary-empty.ctx" \
        /tmp/hff-canary-then.log /tmp/hff-canary-do.log; then
    ok 'canary: a shell keyword does not end command position, so the first command of an if/while body is found'
else
    bad 'canary: the scanner skipped a command that follows a shell keyword, so a fixed path written there would be ignored'
fi
cat > "$work/canary-perrun.sh" <<'CANARY'
log=/tmp/hff-canary.$$.log
nice -n 5 tee "$log"
if true; then tee "$log"; fi
CANARY
canary_perrun_words=$(scanner_items_resolved "$work/canary-perrun.sh" "$work/canary-empty.ctx" \
    | awk -F'\t' '$1 != "#accounting" && $1 != "refuse" { print $3 }' | sort -u | tr '\n' ' ')
if [ "$canary_perrun_words" = '"$log" ' ]; then
    ok 'canary: the same prefixer and keyword shapes with a per-run variable stay the single discovered word "$log" (no fixed-path false positive)'
else
    bad "canary: the prefixer and keyword shapes with a per-run variable produced '$canary_perrun_words', not a single \"\$log\" word"
fi
if is_bare_var_ref '"$cand"'; then
    ok 'canary: the command-word rule treats a bare variable reference the prelude leaves empty as the documented residual (step 2'"'"'s "$cand")'
else
    bad 'canary: the command-word rule refused a bare variable reference the prelude leaves empty, which would red step 2'
fi
if is_bare_var_ref '$(false)'; then
    bad 'canary: the command-word rule accepted a substitution that names no command as a bare variable reference (the carve-out is too wide)'
else
    ok 'canary: the command-word rule does not accept a substitution that resolves to nothing as a bare variable reference'
fi
printf 't=tee\n' > "$work/canary-leadvar.ctx"
printf '%s\n' '$t /tmp/hff-canary-leadvar.log' > "$work/canary-leadvar.sh"
if canary_all_found "$work/canary-leadvar.sh" "$work/canary-leadvar.ctx" /tmp/hff-canary-leadvar.log; then
    ok 'canary: a variable the prelude assigns (t=tee; $t ...) is resolved to its command, so its fixed file argument is found'
else
    bad 'canary: a command word that is a variable the prelude assigns was not resolved, so a fixed path behind it would be ignored'
fi
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
