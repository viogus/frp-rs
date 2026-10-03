#!/usr/bin/env bash
# =============================================================================
# Stray-process guard for the cross-compat harness
# =============================================================================
#
# Sourced by `scripts/compat-test.sh`, and — on its own — by the fixture test
# `scripts/tests/compat-stray-guard.sh`, which drives these functions against
# synthetic `frps` processes. It needs only `TEST_DIR` (the run's scratch
# directory) and `PIDS` (the pids `track_pid` recorded); the caller owns
# `cleanup()` and the `EXIT` trap.
#
# Why this file exists as a unit: the guard is the only thing that catches a
# leaked server, and "it passed" is indistinguishable from "it did not run" — so
# it has to be exercisable without starting a 3-minute compat run.
#
# The contract
# ------------
# Every server a compat run starts holds a config under `$TEST_DIR`, and none
# may outlive the run: a survivor keeps its listeners bound and races the next
# run for the same ports. `cleanup_pids` reaps the pids `track_pid` recorded;
# `assert_no_strays` is the regression test for that contract — it names, reaps
# and fails on the scenario servers still alive after cleanup.
#
# The match is a process name *plus* the scratch directory. The repository's
# stray-process rule forbids name-only kills (a sibling worktree's `frps` is not
# ours and must survive), so `pgrep -x frps` alone is never enough, and reaping
# is by the exact pids printed — never by name.
#
# Measured before the guard (2026-09, `scripts/compat-test.sh --ci`): a green
# run (86 passed, 0 failed, rc 0) left 83 reparented Go servers behind
# (33 `frps`, 50 `frpc`), every one with `PPID 1` and
# `-c /tmp/frp-compat-test/<scenario>/...`.
#
# Hard failure, never a vacuous pass
# ----------------------------------
# The census tools are load-bearing: if `pgrep` is missing or errors, the guard
# would report "no strays" and pass — the exact failure it exists to catch. A
# missing tool, a failing probe, or a degenerate `TEST_DIR` is therefore a hard
# error that refuses to run, not an empty census.
#
# `TEST_DIR=""` also has to be refused: the ownership pattern `*"$TEST_DIR/"*`
# degrades to `*/*` and would flag and kill an unrelated process whose command
# line merely contains a slash.

: "${TEST_DIR:?scripts/lib/compat-stray-guard.sh requires TEST_DIR to be set}"
PIDS="${PIDS:-}"

# Normalise trailing slashes away *before* the refusals below. Every ownership
# match is the literal `"$TEST_DIR/"` (see `scenario_strays`), so a run dir
# spelled with a trailing slash — `FRP_COMPAT_TEST_DIR=/tmp/x/`, which
# `scripts/compat-test.sh:120` documents and shell tab-completion produces —
# became `…/x//` and never matched a command line carrying `…/x/`: the census
# came back empty, the sweep was a no-op, and `assert_no_strays` returned 0 with
# the stray still alive (F2, measured by the adversarial reviewer).
#
# Refusing the spelling loudly was the alternative; normalising was chosen
# because `…/x/` and `…/x` denote the same run directory and it is the guard,
# not the caller, that requires one spelling — a refusal would break an
# override that is otherwise correct. `""` and `/` are still refused below:
# stripping trailing slashes can only shorten a path toward those, never away
# from them.
while [ "$TEST_DIR" != "/" ] && [ "${TEST_DIR%/}" != "$TEST_DIR" ]; do
    TEST_DIR=${TEST_DIR%/}
done

case "$TEST_DIR" in
    ""|/)
        printf 'ERROR: refusing to guard with TEST_DIR=%q: the ownership match would degrade to "anything under a slash"\n' "$TEST_DIR" >&2
        exit 1
        ;;
esac

# Kill all tracked PIDs without removing test dir.
# Resets PIDS so subsequent tests start fresh.
cleanup_pids() {
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
    done
    # Bounded grace period after SIGTERM (graceful drain), then force-kill.
    # Without this, a process whose SIGTERM handler stalls makes the `wait`
    # below hang the whole compat run (observed on CI: 25m job timeout with
    # 60+ orphaned frps/frpc processes after the socks5 scenario).
    local deadline=$((SECONDS + 10))
    while (( SECONDS < deadline )); do
        local alive=""
        for pid in $PIDS; do
            kill -0 "$pid" 2>/dev/null && alive="$alive $pid"
        done
        [[ -z "$alive" ]] && break
        sleep 0.2
    done
    for pid in $PIDS; do
        kill -9 "$pid" 2>/dev/null || true
    done
    # Reap the tracked pids only. A bare `wait` also collects every other live
    # child, so an untracked long-lived child — a helper this script did not
    # start or record — hangs the run here, before the stray guard ever runs.
    for pid in $PIDS; do
        wait "$pid" 2>/dev/null || true
    done
    PIDS=""
}

# Print the pids of this run's scenario servers still alive, one per line.
# Returns 2, after printing why, when the census cannot be taken; never a
# silent empty census. `pgrep` exits 1 when nothing matched — a legitimate
# empty result — and >= 2 on a real failure.
scenario_strays() {
    if ! command -v pgrep >/dev/null 2>&1; then
        printf 'ERROR: the stray guard requires `pgrep`, which is not on PATH; refusing to report an empty census\n' >&2
        return 2
    fi
    if ! command -v ps >/dev/null 2>&1; then
        printf 'ERROR: the stray guard requires `ps`, which is not on PATH; refusing to report an empty census\n' >&2
        return 2
    fi
    local name pid cmd found pids=""
    for name in frps frpc; do
        if found="$(pgrep -x "$name" 2>/dev/null)"; then
            :
        else
            local rc=$?
            if (( rc != 1 )); then
                printf 'ERROR: `pgrep -x %s` failed (status %d); refusing to report an empty census\n' "$name" "$rc" >&2
                return 2
            fi
            found=""
        fi
        pids="$pids $found"
    done
    # Ownership is "the command line contains `$TEST_DIR/`". A scenario server
    # started through a subshell that `cd`s into the scenario dir first — e.g.
    # `( cd "$dir" && exec "$bin" -c frps.toml )` — would carry a relative `-c`
    # and evade the predicate. That shape does not exist in the harness today:
    # all 90 `run_go` call sites pass an absolute `-c "$TEST_DIR/<name>/..."`.
    # If one is ever added, extend this match rather than adding a name-only
    # fallback.
    for pid in $pids; do
        # A probe that cannot describe a *live* pid is not an answer and must not
        # be read as "not ours": that is how a failing `ps` emptied the census
        # while a live in-`TEST_DIR` stray stayed alive (F3, measured by the
        # adversarial reviewer). A pid `pgrep` listed may legitimately have
        # exited before this probe runs — `kill -0` tells that apart from a probe
        # we cannot trust, so the exit race still reads as "not a stray".
        if ! cmd=$(ps -p "$pid" -o command= 2>/dev/null) || [ -z "$cmd" ]; then
            if kill -0 "$pid" 2>/dev/null; then
                printf 'ERROR: cannot read the command line of live pid %s (`ps -p %s -o command=` failed or printed nothing); refusing to report a census that cannot be trusted\n' \
                    "$pid" "$pid" >&2
                return 2
            fi
            continue
        fi
        case "$cmd" in
            *"$TEST_DIR/"*) printf '%s\n' "$pid" ;;
        esac
    done
    return 0
}

# Servers already holding a scenario config when this run started (a sibling
# agent's compat run). They are not ours to reap and must not fail the guard.
#
# **By design, the question is "did *this* run add a stray", not "is any scenario
# server alive"**: a server that predates the run — an earlier crashed run, or a
# sibling's — is forgiven by the baseline. The counterpart: a *different* compat
# run started **after** this baseline still lands in the census and is killed as
# a stray, so two runs must not share a scratch dir — hence
# `TEST_DIR="${FRP_COMPAT_TEST_DIR:-/tmp/frp-compat-test}"` in
# `scripts/compat-test.sh`, which the harness documents in `--help`.
if ! _stray_baseline="$(scenario_strays)"; then
    printf 'ERROR: cannot take the stray baseline (see above); refusing to run with a census that cannot be trusted\n' >&2
    exit 1
fi
STRAY_BASELINE=" $(printf '%s\n' "$_stray_baseline" | tr '\n' ' ') "
unset _stray_baseline

# Name, reap and fail on the servers this run left behind. Only processes `ps`
# still shows are counted, so one that exited between the scan and the check is
# not reported; reaping is by the exact pids printed. Returns 1 so the run's
# exit status reports the regression, and 2 when the census itself failed.
assert_no_strays() {
    local pid line report="" survivors="" strays
    if ! strays="$(scenario_strays)"; then
        return 2
    fi
    for pid in $strays; do
        case "$STRAY_BASELINE" in
            *" $pid "*) continue ;;
        esac
        # Same rule as the census: a probe that cannot describe a live pid is a
        # census that cannot be trusted, not "the stray went away". A pid that
        # genuinely exited between the scan and this read is still skipped (see
        # above), which `kill -0` is what distinguishes (F3).
        if ! line=$(ps -p "$pid" -o pid=,ppid=,command= 2>/dev/null) || [[ -z "$line" ]]; then
            if kill -0 "$pid" 2>/dev/null; then
                printf 'ERROR: cannot read the command line of live stray pid %s (`ps -p %s -o pid=,ppid=,command=` failed or printed nothing); refusing to report a census that cannot be trusted\n' \
                    "$pid" "$pid" >&2
                return 2
            fi
            continue
        fi
        survivors="$survivors $pid"
        report="${report}  ${line}
"
    done
    if [[ -z "$survivors" ]]; then
        return 0
    fi
    printf 'ERROR: compat run left stray server process(es) behind:\n%s' "$report" >&2
    kill -9 $survivors 2>/dev/null || true
    return 1
}

# Reap the in-`$TEST_DIR` strays this run did not inherit, by the exact pids the
# census printed, honouring the baseline like `assert_no_strays` does: a server
# that predates this run (a sibling's, or an earlier crashed run's) is not ours
# and is left alone. This is the mid-run sweep for a helper that starts several
# servers per scenario (`run_xtcp_test`, which used to `pkill -f "frpc -c"` /
# `pkill -f "frps -c"`): it stops a previous scenario's leftover from holding a
# port or reconnecting with a stale token, before the next scenario's servers
# start. No argument pattern is ever matched here.
#
# Best effort by design: if the census itself fails (missing `pgrep`, a failing
# `ps`), there is nothing to reap and this returns 0 rather than guessing; the
# *failure* signal belongs to `assert_no_strays` in the run's exit trap, which
# refuses an unusable census instead of sweeping on a hunch.
reap_scoped_strays() {
    local pid strays
    if ! strays="$(scenario_strays)"; then
        return 0
    fi
    for pid in $strays; do
        case "$STRAY_BASELINE" in
            *" $pid "*) continue ;;
        esac
        kill -9 "$pid" 2>/dev/null || true
    done
    return 0
}
