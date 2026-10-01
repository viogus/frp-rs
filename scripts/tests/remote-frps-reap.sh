#!/usr/bin/env bash
# =============================================================================
# Fixture: the remote frps helper's exact-pid reap route (TODO.md:9114)
# =============================================================================
#
# `scripts/remote-frps.sh` used to manage the comparison server on a remote VPS
# with `pkill -f 'frps -c frps.toml'` (start and stop) and `pgrep -f` on the
# same text (status). Name plus argument selects *any* process on the VPS whose
# command line carries the text — the hazard the local compat sweep already
# lost — and the remote side could not copy the local fix: over an ssh hop there
# is no `$TEST_DIR/` ownership prefix and no baseline census to subtract.
#
# The replacement is a pid file written by the same remote command that starts
# the server (`scripts/lib/remote-frps-reap.sh`), read back by exact pid. This
# suite drives the real fragments — the same text `remote-frps.sh` interpolates
# into its ssh commands — through `bash -c` against synthetic servers, so no
# sshd, no VPS and no repo binary is involved.
#
# Scenarios
#   A  the start fragment records the server's exact pid in the directory it
#      started the server in, and that pid really is that server.
#   B  the reap fragment, pointed at one directory's pid file, reaps that server
#      while a *second* server started the same way — same command line, same
#      matching text — survives; naming the second pid file reaps it too, so the
#      survival is scoping, not a reaper that never worked.
#   C  an already-dead pid is a no-op (rc 0; a live witness is untouched).
#   D  a missing pid file is a no-op (rc 0; a live server whose pid file was
#      removed is untouched).
#   E  the run-directory sweep reaps and removes the run directories under a
#      root and leaves a server outside those names alone.
#   F  the status census answers from pid files only: a live process whose
#      command line carries the matched text, with no pid file anywhere, is
#      `stopped` — never `running (no pid file)`.
#   G  the helper's own code carries no `pkill`/`killall`/`pgrep -f` and routes
#      start/reap/status through the library (the source-shape half; without a
#      run of the fragments a source check alone can rot behind a comment).
#
# Self-contained: no network, no ssh, no dependence on this repo's binaries.
# Synthetic servers and the scratch tree are removed on exit.
#
# Usage: bash scripts/tests/remote-frps-reap.sh
set -uo pipefail

self=${BASH_SOURCE[0]:-$0}
ROOT=$(cd -P -- "$(dirname -- "$self")/../.." && pwd)
LIB="$ROOT/scripts/lib/remote-frps-reap.sh"
HELPER="$ROOT/scripts/remote-frps.sh"

checks=0
fails=0
# Pinned floor. A suite that exits early — a neutered scenario body, a deleted
# case — leaves every remaining assertion green, so the count has to be
# enforced from the EXIT trap, which is installed before the first check.
MIN_CHECKS=31

ok()  { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf '  FAIL  %s\n' "$1"; }
hdr() { printf '\n%s\n' "$1"; }

# Every synthetic pid this suite starts, reaped on exit even if a scenario
# failed early.
LIVE=""

cleanup_all() {
    local rc=$? pid
    trap - EXIT
    for pid in $LIVE; do
        kill -9 "$pid" 2>/dev/null || true
    done
    if [ -n "${WORK:-}" ]; then
        rm -rf "$WORK"
    fi
    if [ "$checks" -lt "$MIN_CHECKS" ]; then
        bad "floor: only $checks of $MIN_CHECKS checks ran — an early exit cannot report a passing suite"
    fi
    printf '\nRESULT: %s fixture check(s) hold\n' "$((checks - fails))"
    if [ "$fails" -ne 0 ]; then
        exit 1
    fi
    exit "$rc"
}
trap cleanup_all EXIT

for tool in ps sleep sed grep; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'FAIL  this fixture harness needs %s on PATH\n' "$tool"
        exit 1
    }
done
if [ ! -f "$LIB" ]; then
    printf 'FAIL  missing %s — the reap route this suite drives is not there\n' "$LIB"
    exit 1
fi

# shellcheck source-path=SCRIPTDIR
# shellcheck source=../lib/remote-frps-reap.sh
source "$LIB"

# Short paths: the command-line assertions below compare against what `ps`
# prints, and a long `TMPDIR` would put them near a `ps` truncation width.
WORK=$(mktemp -d /tmp/rfr-reap.XXXXXX) || {
    printf 'FAIL  cannot create a scratch directory under /tmp\n'
    exit 1
}

# A synthetic `frps`: one long-lived process whose command line carries the
# exact text the old pattern matched (`exec -a`, so no interpreter is left
# waiting behind it and a SIGTERM to the recorded pid reaches the server
# itself). `$PWD` is expanded where the start fragment `cd`s to.
write_fake_frps() {  # <dir>
    local dir="$1"
    cat > "$dir/frps" <<'FAKE'
#!/bin/bash
exec -a "$PWD/frps -c frps.toml" sleep 120
FAKE
    chmod +x "$dir/frps"
}

# Start a server through the *real* start fragment. Sets `start_rc` and
# `start_pid` (empty when the pid file is missing or unreadable).
start_rc=0
start_pid=""
start_server() {  # <dir>
    local dir="$1"
    mkdir -p "$dir" || return 1
    write_fake_frps "$dir"
    bash -c "$(remote_start_snippet "$dir")" >/dev/null 2>&1
    start_rc=$?
    start_pid=""
    if [ -f "$dir/frps.pid" ]; then
        start_pid=$(cat "$dir/frps.pid" 2>/dev/null || true)
    fi
    case "$start_pid" in
        ''|*[!0-9]*) ;;
        *) LIVE="$LIVE $start_pid" ;;
    esac
    return 0
}

# Run a fragment the way the remote shell would.
run_fragment() {  # <fragment-text>
    bash -c "$1" 2>/dev/null
}

wait_gone() {  # <pid>
    local pid="$1"
    for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.1
    done
    return 1
}

pid_alive() {  # <pid>
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    kill -0 "$1" 2>/dev/null
}

cmdline_of() {  # <pid>
    ps -p "$1" -o command= 2>/dev/null || true
}

# The synthetic server execs into a single `sleep` carrying a synthetic
# argv[0]; until that exec lands, `ps` shows the interpreter and the relative
# `./frps`. Both shapes are "ours", so poll rather than race a fixed sleep.
cmdline_carries() {  # <pid> <text>
    local pid="$1" want="$2"
    for _ in $(seq 1 50); do
        case "$(cmdline_of "$pid")" in
            *"$want"*) return 0 ;;
        esac
        sleep 0.1
    done
    return 1
}

strip_comments() {  # <file>
    sed 's/[[:space:]]*#.*$//' "$1"
}

# `pkill -f`/`pgrep -f` match a process's full command line; this argument-pattern
# regex is what the replacement must not reintroduce (comments are stripped
# first, because the rationale for the route names the commands it replaced).
pattern_hits() {  # <file>
    strip_comments "$1" \
        | grep -nE '(^|[^[:alnum:]_])(pkill|killall)([[:space:]]|$)|(^|[^[:alnum:]_])pgrep[[:space:]]+-[^[:space:]]*f' \
        || true
}

# ------------------------------------------------------------------ scenario A
hdr 'scenario A: the start fragment records the exact pid where it starts the server'
own_dir="$WORK/own"
start_server "$own_dir"
own_pid=$start_pid
if [ "$start_rc" -eq 0 ]; then
    ok 'start fragment: exited 0'
else
    bad "start fragment: exited $start_rc"
fi
if [ -f "$own_dir/frps.pid" ]; then
    ok 'start fragment: wrote frps.pid in the directory it started the server in'
else
    bad "start fragment: no $own_dir/frps.pid after start"
fi
if pid_alive "$own_pid"; then
    ok "start fragment: recorded a live pid ($own_pid)"
else
    bad "start fragment: recorded pid '$own_pid' is not a live process"
fi
if cmdline_carries "$own_pid" 'frps -c frps.toml'; then
    ok 'start fragment: the recorded pid command line carries frps -c frps.toml'
else
    bad "start fragment: pid $own_pid command line does not carry frps -c frps.toml: $(cmdline_of "$own_pid")"
fi
if cmdline_carries "$own_pid" "$own_dir/frps"; then
    ok 'start fragment: the recorded pid is the server in that directory, not another process'
else
    bad "start fragment: pid $own_pid is not the server under $own_dir: $(cmdline_of "$own_pid")"
fi

# ------------------------------------------------------------------ scenario B
# Both servers are started exactly the same way and both command lines carry the
# text the old sweep matched (asserted, so a reaper that silently stopped
# working cannot pass this scenario). Only the directory named to the reap may
# die.
hdr 'scenario B: the pid file scopes the reap — a same-command-line decoy survives'
decoy_dir="$WORK/decoy"
start_server "$decoy_dir"
decoy_pid=$start_pid
if pid_alive "$decoy_pid"; then
    ok "decoy: a second server started the same way is live ($decoy_pid)"
else
    bad "decoy: second server did not start (pid '$decoy_pid')"
fi
if cmdline_carries "$decoy_pid" 'frps -c frps.toml'; then
    ok 'decoy: its command line carries the text the old pattern matched (not a vacuous decoy)'
else
    bad "decoy: pid $decoy_pid command line does not carry frps -c frps.toml; the scenario would be vacuous"
fi

run_fragment "$(remote_reap_pidfile_snippet "$own_dir/frps.pid")"
reap_rc=$?
if [ "$reap_rc" -eq 0 ]; then
    ok 'reap: reaping by pid file exited 0'
else
    bad "reap: reaping by pid file exited $reap_rc"
fi
if wait_gone "$own_pid"; then
    ok "reap: the helper's own server ($own_pid) was reaped"
else
    bad "reap: the helper's own server ($own_pid) survived its pid file"
fi
if pid_alive "$decoy_pid"; then
    ok "reap: the decoy whose command line carries frps -c frps.toml survived ($decoy_pid)"
else
    bad "reap: the decoy ($decoy_pid) was reaped — the route is not scoped to the pid file"
fi
run_fragment "$(remote_reap_pidfile_snippet "$decoy_dir/frps.pid")"
reap_rc=$?
if [ "$reap_rc" -eq 0 ] && wait_gone "$decoy_pid"; then
    ok 'reap: the same route reaps the decoy when its own pid file is the one named'
else
    bad "reap: the route did not reap the decoy from its own pid file (rc=$reap_rc, pid=$decoy_pid)"
fi

# ------------------------------------------------------------------ scenario C
hdr 'scenario C: an already-dead pid is a no-op'
witness_dir="$WORK/witness"
start_server "$witness_dir"
witness_pid=$start_pid
stale_dir="$WORK/stale"
start_server "$stale_dir"
stale_pid=$start_pid
kill -9 "$stale_pid" 2>/dev/null || true
if wait_gone "$stale_pid" && pid_alive "$witness_pid"; then
    ok "stale: the recorded pid ($stale_pid) is dead and the witness ($witness_pid) is live before the reap"
else
    bad "stale: setup failed (stale alive=$(pid_alive "$stale_pid" && echo yes || echo no), witness alive=$(pid_alive "$witness_pid" && echo yes || echo no))"
fi
run_fragment "$(remote_reap_pidfile_snippet "$stale_dir/frps.pid")"
reap_rc=$?
if [ "$reap_rc" -eq 0 ]; then
    ok 'stale: reaping an already-dead pid exited 0'
else
    bad "stale: reaping an already-dead pid exited $reap_rc"
fi
if pid_alive "$witness_pid"; then
    ok 'stale: the live witness was untouched'
else
    bad 'stale: the live witness died — the reap is not limited to the recorded pid'
fi

# ------------------------------------------------------------------ scenario D
hdr 'scenario D: a missing pid file is a no-op'
missing_dir="$WORK/missing"
start_server "$missing_dir"
missing_pid=$start_pid
rm -f "$missing_dir/frps.pid"
if pid_alive "$missing_pid" && [ ! -f "$missing_dir/frps.pid" ]; then
    ok "missing: the server ($missing_pid) is live and its pid file is gone"
else
    bad "missing: setup failed (alive=$(pid_alive "$missing_pid" && echo yes || echo no))"
fi
run_fragment "$(remote_reap_pidfile_snippet "$missing_dir/frps.pid")"
reap_rc=$?
if [ "$reap_rc" -eq 0 ]; then
    ok 'missing: reaping with no pid file exited 0'
else
    bad "missing: reaping with no pid file exited $reap_rc"
fi
if pid_alive "$missing_pid"; then
    ok 'missing: the unrecorded server was left alone'
else
    bad 'missing: the unrecorded server was reaped — a missing pid file must not license a guess'
fi

# ------------------------------------------------------------------ scenario E
hdr 'scenario E: the run-directory sweep reaps by pid file and leaves other servers alone'
root="$WORK/root"
start_server "$root/frp-xtcp-AAAAAA"
rd1_pid=$start_pid
start_server "$root/frp-xtcp-BBBBBB"
rd2_pid=$start_pid
start_server "$root/frp-xtcp-test"
legacy_pid=$start_pid
outside_dir="$WORK/outside"
start_server "$outside_dir"
outside_pid=$start_pid
run_fragment "$(remote_reap_rundirs_snippet "$root")"
reap_rc=$?
if [ "$reap_rc" -eq 0 ]; then
    ok 'rundirs: the sweep exited 0'
else
    bad "rundirs: the sweep exited $reap_rc"
fi
if wait_gone "$rd1_pid" && wait_gone "$rd2_pid"; then
    ok "rundirs: both run directories' servers were reaped ($rd1_pid, $rd2_pid)"
else
    bad "rundirs: a run directory server survived (rd1=$rd1_pid alive=$(pid_alive "$rd1_pid" && echo yes || echo no), rd2=$rd2_pid alive=$(pid_alive "$rd2_pid" && echo yes || echo no))"
fi
if wait_gone "$legacy_pid"; then
    ok "rundirs: the legacy frp-xtcp-test directory's server was reaped ($legacy_pid)"
else
    bad "rundirs: the legacy directory's server survived ($legacy_pid)"
fi
if [ ! -d "$root/frp-xtcp-AAAAAA" ] && [ ! -d "$root/frp-xtcp-BBBBBB" ] && [ ! -d "$root/frp-xtcp-test" ]; then
    ok 'rundirs: the reaped run directories were removed'
else
    bad 'rundirs: a reaped run directory is still present'
fi
if pid_alive "$outside_pid" && [ -d "$outside_dir" ]; then
    ok "rundirs: a server outside the run-directory names survived ($outside_pid)"
else
    bad 'rundirs: a server outside the run-directory names was reaped or its directory removed'
fi

# ------------------------------------------------------------------ scenario F
hdr 'scenario F: the status census answers from pid files, never from a command line'
status_root="$WORK/status"
start_server "$status_root/frp-xtcp-AAAAAA"
spid=$start_pid
out=$(run_fragment "$(remote_status_scan_snippet "$status_root")")
case "$out" in
    "running (pid=$spid, dir=$status_root/frp-xtcp-AAAAAA)")
        ok 'status: a run directory with a live pid file reports running' ;;
    *)
        bad "status: expected 'running (pid=$spid, ...)', got '$out'" ;;
esac
kill -9 "$spid" 2>/dev/null || true
wait_gone "$spid" || true
out=$(run_fragment "$(remote_status_scan_snippet "$status_root")")
# The census prints one line per run directory and then, because a directory
# existed, the aggregate `stopped (stale)` — the pre-existing shape for this
# path, kept identical here.
case "$out" in
    *"stopped (stale pid=$spid, dir=$status_root/frp-xtcp-AAAAAA)"*)
        ok 'status: a stale pid file reports stopped (stale …)' ;;
    *)
        bad "status: expected 'stopped (stale pid=$spid, …)', got '$out'" ;;
esac
legacy_root="$WORK/status-legacy"
mkdir -p "$legacy_root/frp-xtcp-test"
start_server "$legacy_root/frp-xtcp-test"
lpid=$start_pid
out=$(run_fragment "$(remote_status_scan_snippet "$legacy_root")")
case "$out" in
    "running (pid=$lpid)")
        ok 'status: the legacy frp-xtcp-test pid file reports running' ;;
    *)
        bad "status: expected 'running (pid=$lpid)', got '$out'" ;;
esac
# The regression this replaces: a live process whose command line carries the
# matched text, with no pid file anywhere, used to answer `running (no pid
# file)` off `pgrep -f`. There is no exact pid on record, so the honest answer
# is that nothing is known to be running.
control_dir="$WORK/control"
start_server "$control_dir"
control_pid=$start_pid
if pid_alive "$control_pid" && cmdline_carries "$control_pid" 'frps -c frps.toml'; then
    ok 'status: a live matching process exists outside the census root'
else
    bad "status: the control server is not live and matching ($control_pid); the no-pid-file check would be vacuous"
fi
empty_root="$WORK/status-empty"
mkdir -p "$empty_root"
out=$(run_fragment "$(remote_status_scan_snippet "$empty_root")")
if [ "$out" = 'stopped' ]; then
    ok 'status: a live matching process with no pid file reports stopped (the pgrep fallback is gone)'
else
    bad "status: expected 'stopped' with no pid file anywhere, got '$out'"
fi
if pid_alive "$control_pid"; then
    ok 'status: the census is read-only — the matching process is still alive'
else
    bad 'status: the census killed a process'
fi

# ------------------------------------------------------------------ scenario G
hdr 'scenario G: the helper routes start/reap/status through the library'
hits=$(pattern_hits "$HELPER")
if [ -z "$hits" ]; then
    ok 'remote-frps.sh: no pkill/killall/pgrep -f in its code'
else
    bad "remote-frps.sh kills by pattern again: $(printf '%s' "$hits" | tr '\n' ' ')"
fi
hits=$(pattern_hits "$LIB")
if [ -z "$hits" ]; then
    ok 'remote-frps-reap.sh: no pkill/killall/pgrep -f in its code'
else
    bad "remote-frps-reap.sh kills by pattern: $(printf '%s' "$hits" | tr '\n' ' ')"
fi
helper_code=$(strip_comments "$HELPER")
missing=""
for fn in remote_start_snippet remote_reap_pidfile_snippet remote_reap_rundirs_snippet remote_status_scan_snippet; do
    case "$helper_code" in
        *"$fn"*) ;;
        *) missing="$missing $fn" ;;
    esac
done
# `$SCRIPT_DIR` is matched literally here, not expanded.
# shellcheck disable=SC2016
case "$helper_code" in
    *'source "$SCRIPT_DIR/lib/remote-frps-reap.sh"'*) ;;
    *) missing="$missing source-lib" ;;
esac
if [ -z "$missing" ]; then
    ok 'remote-frps.sh: sources the library and calls the start/reap/rundirs/status fragments'
else
    bad "remote-frps.sh: does not route through the library (missing:$missing)"
fi
