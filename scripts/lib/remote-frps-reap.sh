#!/usr/bin/env bash
# =============================================================================
# Exact-pid reap route for the remote XTCP frps helper
# =============================================================================
#
# Sourced by `scripts/remote-frps.sh`, and — on its own — by the fixture test
# `scripts/tests/remote-frps-reap.sh`, which drives the emitted fragments
# against synthetic `frps` processes.
#
# Why this file exists as a unit: the remote helper used to manage the
# comparison server with `pkill -f 'frps -c frps.toml'` / `pgrep -f` over ssh
# (`TODO.md:10529`). Name plus argument selects *any* process on the VPS whose
# command line carries that text — the same hazard the local compat sweep
# already lost (PR #430) — and the local fix cannot be copied: over an ssh hop
# there is no `$TEST_DIR/` ownership prefix and no baseline census to subtract
# (`reap_scoped_strays` in `scripts/lib/compat-stray-guard.sh` relies on both).
# The remote route is therefore a pid file written *where the server is
# started*, read back by exact pid.
#
# The contract
# ------------
# `remote-frps.sh` starts frps through `remote_start_snippet`, which records the
# server's exact pid in `<dir>/frps.pid` in the same remote command that starts
# it. Every later reap and every liveness decision goes through that pid file:
# `remote_reap_pidfile_snippet` (SIGTERM, a bounded grace period, SIGKILL),
# `remote_reap_rundirs_snippet` (the same, per run directory under a root) and
# `remote_status_scan_snippet` (a census of pid files, never of command lines).
# No fragment here matches an argument pattern, and none of them needs `pgrep`
# or `pkill` on the remote host.
#
# What a missing pid file means
# -----------------------------
# "No pid on record" is a no-op, not a licence to guess: a reap with no pid file
# does nothing, and the status census reports `stopped` for a live process it
# cannot name by pid. That is the deliberate replacement for the old
# `running (no pid file)` answer, which was derived from a command-line match.
#
# What the pid file does not do
# -----------------------------
# It names a pid, not an identity. A *stale* pid file whose pid has since been
# reused by an unrelated process would be killed by the next pre-flight. That
# window belongs to the pid file itself — the file is removed with its directory
# on every stop and every pre-flight — and it is far narrower than the
# name-plus-argument match this replaces, which reaped every matching process on
# the host. An identity check on the reap path would have to read the target's
# command line, which is the same argument-pattern match again, only anchored to
# a path; it is deliberately not here.
#
# Only a positive integer is a pid. `0` is not: `kill -0 0` succeeds and `kill 0`
# signals the calling process's whole process group, and a negative value
# signals a process group too. The guard is therefore `[ "$pid" -gt 0 ]`, not
# `[ -n "$pid" ]` — which also rejects an empty file and a *multi-line* one,
# whose `cat` yields embedded newlines. The multi-line case is a declared bound,
# not a fix: the pid is refused (so no wrong process is signalled) while
# `remote_reap_rundirs_snippet` still removes the directory, so the live target
# is missed until the port band or a manual clean-up catches it.
# Emitted text, not remote functions
# ----------------------------------
# What crosses the ssh hop is a shell string, so these functions *emit* the
# remote fragment and the caller interpolates it into its remote command. The
# fragments expand `$pid` / `$!` / `$d` on the remote side, so an emitting
# function is always called from a command substitution — whose output the local
# shell does not re-expand — and `remote-frps.sh` never lets a fragment's own
# `$` reach the local shell. The fixture runs the same text through `bash -c`,
# which is how the real route is exercised without an sshd.

# Emit the remote fragment that starts frps in <dir> and records its exact pid
# in <dir>/frps.pid.
#
# The pid is `$!` of the backgrounded `nohup`, and it is the server's own pid:
# `nohup` execs the command instead of forking, and `nohup … &` inside a `( … )`
# is a *simple* command, so `$!` is that command's pid rather than a subshell's.
# Backgrounding a `cd … && … &` list instead — as this call site used to — makes
# `$!` the pid of the list's subshell, which may or may not have exec'd the
# server.
remote_start_snippet() {
    local dir="$1"
    printf '%s\n' \
        "cd '$dir' && chmod +x frps && ( nohup ./frps -c frps.toml > frps.log 2>&1 < /dev/null & echo \$! > frps.pid )"
}

# Emit the remote fragment that reaps exactly the pid recorded in <pidfile>:
# SIGTERM, 0.3 s of grace, then SIGKILL. A missing file, an empty file or an
# already-dead pid is a no-op.
#
# <pidfile> is the path as the *remote* shell should read it, and it is
# double-quoted into the fragment: pass a literal path, or an unexpanded remote
# expression such as `$d/frps.pid` (single-quoted by the caller so the local
# shell leaves it alone) when the fragment lands inside a remote loop.
remote_reap_pidfile_snippet() {
    local pidfile="$1"
    printf '%s\n' \
        "if [ -f \"$pidfile\" ]; then" \
        "    pid=\$(cat \"$pidfile\" 2>/dev/null)" \
        "    if [ \"\$pid\" -gt 0 ] 2>/dev/null; then" \
        "        kill -0 \"\$pid\" 2>/dev/null && kill \"\$pid\" 2>/dev/null || true" \
        "        sleep 0.3" \
        "        kill -0 \"\$pid\" 2>/dev/null && kill -9 \"\$pid\" 2>/dev/null || true" \
        "    fi" \
        "fi"
}

# Emit the remote fragment that reaps every run directory under <root> (the
# remote `/tmp` in production) by its own pid file, then removes the directory.
# The glob and `[ -d ]` guard keep this to directories this helper's own start
# path created; a process whose command line merely contains `frps -c frps.toml`
# is not addressable here at all.
remote_reap_rundirs_snippet() {
    local root="$1" reap
    # `$d` is deliberately single-quoted: it must reach the *remote* loop
    # unexpanded, and passing it through a command substitution is what keeps
    # the local shell out of it (see the file header).
    # shellcheck disable=SC2016
    reap=$(remote_reap_pidfile_snippet '$d/frps.pid')
    printf '%s\n' \
        "for d in $root/frp-xtcp-?????? $root/frp-xtcp-test; do" \
        "    if [ -d \"\$d\" ]; then" \
        "$reap" \
        "        rm -rf \"\$d\" 2>/dev/null" \
        "    fi" \
        "done"
}

# Emit the remote census for the non-shard status path: walk the run dirs under
# <root> and report the state each pid file records. A pid file naming a live
# pid is `running`; a stale one is `stopped (stale …)`; no pid file anywhere is
# `stopped`, even when a matching-looking process is alive — there is no exact
# pid to name it by, and inventing one from a command-line match is the
# behaviour this replaces.
remote_status_scan_snippet() {
    local root="$1"
    printf '%s\n' \
        "found=0" \
        "for d in $root/frp-xtcp-??????; do" \
        "    if [ -d \"\$d\" ]; then" \
        "        found=1" \
        "        PID_FILE=\"\$d/frps.pid\"" \
        "        if [ -f \"\$PID_FILE\" ]; then" \
        "            pid=\$(cat \"\$PID_FILE\")" \
        "            if kill -0 \"\$pid\" 2>/dev/null; then" \
        "                echo \"running (pid=\$pid, dir=\$d)\"" \
        "                exit 0" \
        "            else" \
        "                echo \"stopped (stale pid=\$pid, dir=\$d)\"" \
        "            fi" \
        "        fi" \
        "    fi" \
        "done" \
        "if [ -f \"$root/frp-xtcp-test/frps.pid\" ]; then" \
        "    pid=\$(cat \"$root/frp-xtcp-test/frps.pid\")" \
        "    if kill -0 \"\$pid\" 2>/dev/null; then" \
        "        echo \"running (pid=\$pid)\"" \
        "        exit 0" \
        "    fi" \
        "fi" \
        "if [ \$found -eq 1 ]; then" \
        "    echo \"stopped (stale)\"" \
        "else" \
        "    echo \"stopped\"" \
        "fi"
}
