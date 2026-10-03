#!/usr/bin/env bash
# compat-port-ownership.sh — the compat harness's port ledger and LISTEN-socket
# ownership checks.
#
# Two harness failures live here:
#
#   * `random_port()` (`scripts/compat-test.sh`) picks a port without
#     remembering the ones it has already handed out, so one scenario can be
#     given the same port twice — its echo listener and its frps, say;
#   * a readiness probe accepts any socket that answers, so a scenario's own
#     echo listener (or a leftover from an earlier scenario, or a foreign
#     process) satisfies a gate meant for the frps/frpc that was just launched.
#
# Both are answered from one place.
#
# ledger — `cpo_pick_port` records every port it returns in
#   `$TEST_DIR/allocated-ports.$$` and refuses a port already recorded there, so
#   one run never hands out the same port twice. A *file*, not a shell variable,
#   because callers use `$(random_port)` — a command substitution runs in a
#   subshell, so a global written inside it would be discarded. `$$` is the
#   parent shell's pid even inside `$( )`, so every subshell of one run shares
#   the file. It is written once per run (`TEST_DIR` is wiped at startup) and
#   removed with `TEST_DIR`.
#
# ownership — `cpo_listen_owner` names the pid that owns a LISTEN socket (lsof,
#   else ss). `cpo_ready_owned` accepts an owner only when it is a pid this run
#   started (`$PIDS`, as `track_pid` accumulates it) and, for a port an
#   auxiliary listener was registered on (`cpo_register_listener`, called by
#   `start_echo_server` and friends), only while no *non-auxiliary* process has
#   been launched since that listener started: the registration carries the
#   caller's launch generation (`$AUX_LAUNCH_GEN`, bumped by `track_pid` and not
#   by `track_aux_pid`), and a mismatch means the scenario handed its own echo
#   listener the port a later frps/frpc was meant to take. That is the
#   collision tooth: a scenario that gives two listeners one port cannot pass
#   the later process's gate.
#
# Fail-closed rules:
#   * neither lsof nor ss installed -> `cpo_listen_owner` returns 2 ("cannot
#     tell") and every readiness gate refuses to report the port ready. The old
#     `wait_for_port_safe` fell back to `nc -z` and, with no probe at all, to
#     `sleep` + `return 0` — a vacuous pass.
#   * `TEST_DIR` empty or `/` -> the ledger refuses to write: `/allocated-ports.$$`
#     is not a run scratch file. The same two shapes are refused by
#     `scripts/lib/compat-stray-guard.sh`.
#   * a LISTEN socket owned by nobody this run started -> `cpo_ready_owned`
#     returns 3 and says whose socket it is, so the caller fails at once instead
#     of waiting out its timeout.
#
# Contract (the caller sets these before sourcing):
#   TEST_DIR          run scratch dir; the ledger lives here.
#   PIDS              pids this run started, space-separated as `track_pid` builds it.
#   AUX_LAUNCH_GEN    how many non-auxiliary processes this run has launched; the
#                     auxiliary listener registration records it and a readiness
#                     gate compares against it (default 0).
# Fixture seam:
#   CPO_PORT_MIN / CPO_PORT_MAX  draw range, default 17000 / 26999.
#
# The fixture suite `scripts/tests/compat-port-ownership.sh` drives every
# function here against real listeners; nothing in this file shells out to frp.

# --- ledger -----------------------------------------------------------------

cpo_ledger_ok() {
    # A ledger needs a run scratch dir; `/allocated-ports.$$` is not one. rc 1
    # and a message when TEST_DIR is unset, empty or "/".
    case "${TEST_DIR:-}" in
        "" | "/")
            printf 'ERROR: compat-port-ownership: TEST_DIR is %s; refusing a port ledger there\n' \
                "${TEST_DIR:-<unset>}" >&2
            return 1
            ;;
    esac
    return 0
}

cpo_ports_file() { printf '%s/allocated-ports.%s\n' "$TEST_DIR" "$$"; }

cpo_listeners_file() { printf '%s/listeners.%s\n' "$TEST_DIR" "$$"; }

cpo_port_allocated() {
    # rc 0 = this run already handed this port out, 1 = it did not, 2 = no usable
    # TEST_DIR (the ledger cannot answer).
    local port="$1" file
    cpo_ledger_ok || return 2
    file=$(cpo_ports_file)
    [[ -f "$file" ]] || return 1
    grep -qx -- "$port" "$file" 2>/dev/null
}

cpo_allocate_port() {
    # Record a port as handed out. Idempotent. rc 2 (after a message) when the
    # ledger cannot be written — a pick that cannot remember its port must not
    # report success.
    local port="$1" file
    cpo_ledger_ok || return 2
    file=$(cpo_ports_file)
    if [[ -f "$file" ]] && grep -qx -- "$port" "$file" 2>/dev/null; then
        return 0
    fi
    mkdir -p -- "$TEST_DIR" 2>/dev/null || {
        printf 'ERROR: compat-port-ownership: cannot create TEST_DIR %s for the port ledger\n' \
            "$TEST_DIR" >&2
        return 2
    }
    printf '%s\n' "$port" >>"$file" || return 2
    return 0
}

cpo_ledger_reset() {
    # Fixtures only: forget every port and auxiliary listener recorded so far.
    cpo_ledger_ok || return 2
    rm -f -- "$(cpo_ports_file)" "$(cpo_listeners_file)"
    return 0
}

cpo_port_listening() {
    # rc 0 = something is listening or bound on this port now. Used only by the
    # picker; with no census tool it says "free" (the pre-existing behaviour).
    # The readiness gates do NOT use this: they fail closed (see `cpo_ready_owned`).
    local port="$1"
    if command -v lsof >/dev/null 2>&1; then
        if lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | grep -q LISTEN; then
            return 0
        fi
        if lsof -nP -iUDP:"$port" 2>/dev/null | grep -q .; then
            return 0
        fi
        return 1
    fi
    if command -v ss >/dev/null 2>&1; then
        if ss -tln "sport = :$port" 2>/dev/null | grep -q ":$port "; then
            return 0
        fi
        if ss -uln "sport = :$port" 2>/dev/null | grep -q ":$port "; then
            return 0
        fi
        return 1
    fi
    return 1
}

cpo_pick_port() {
    # Print a port this run has not handed out and that nothing holds. Bounded:
    # one sweep of the range, then a loud failure naming the range (the old loop
    # had no bound and no memory).
    local min="${CPO_PORT_MIN:-17000}" max="${CPO_PORT_MAX:-26999}"
    local span=$(( max - min + 1 )) tries port i st=0
    if (( span <= 0 )); then
        printf 'ERROR: compat-port-ownership: empty port range %s-%s\n' "$min" "$max" >&2
        return 1
    fi
    tries="$span"
    for (( i = 0; i < tries; i++ )); do
        port=$(( (RANDOM % span) + min ))
        st=0
        cpo_port_allocated "$port" || st=$?
        case $st in
            0) continue ;;
            2) return 2 ;;
        esac
        cpo_port_listening "$port" && continue
        cpo_allocate_port "$port" || return 2
        printf '%s\n' "$port"
        return 0
    done
    printf 'ERROR: compat-port-ownership: no free port in %s-%s after %s draws (all allocated this run or in use)\n' \
        "$min" "$max" "$tries" >&2
    return 1
}

# --- ownership ---------------------------------------------------------------

cpo_listen_owner() {
    # Print the pid(s) that own a LISTEN socket on port $1, one per line.
    # rc 0 = printed, 1 = nobody is listening, 2 = cannot tell (no lsof, no ss).
    local port="$1" out=""
    if command -v lsof >/dev/null 2>&1; then
        out=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null) || out=""
        [[ -n "$out" ]] || return 1
        printf '%s\n' "$out"
        return 0
    fi
    if command -v ss >/dev/null 2>&1; then
        out=$(ss -tlnp "sport = :$port" 2>/dev/null) || out=""
        [[ -n "$out" ]] || return 1
        out=$(printf '%s\n' "$out" | grep -o 'pid=[0-9]*' | sed 's/^pid=//')
        [[ -n "$out" ]] || return 1
        printf '%s\n' "$out"
        return 0
    fi
    return 2
}

cpo_pid_tracked() {
    # rc 0 when $1 is one of the pids this run started.
    local pid="$1"
    [[ -n "${PIDS:-}" ]] || return 1
    case " $PIDS " in
        *" $pid "*) return 0 ;;
    esac
    return 1
}

cpo_register_listener() {
    # $1=role $2=port $3=pid $4=launch generation — record that this run started
    # an auxiliary listener on this port, so a later gate can tell "the listener
    # I just started" from "something squatting the port the process I launched
    # next was meant to take". A registration stops being a valid owner as soon
    # as a non-auxiliary process is launched (see `cpo_ready_owned`).
    local role="$1" port="$2" pid="$3" gen="${4:-0}" file
    cpo_ledger_ok || return 2
    mkdir -p -- "$TEST_DIR" 2>/dev/null || return 2
    file=$(cpo_listeners_file)
    printf '%s %s %s %s\n' "$role" "$port" "$pid" "$gen" >>"$file" || return 2
    return 0
}

cpo_listener_roles() {
    # Print "<role> <pid> <generation>" for every auxiliary listener this run
    # registered on port $1; rc 1 with no output when there is none.
    local port="$1" file role lport lpid lgen out=""
    cpo_ledger_ok || return 1
    file=$(cpo_listeners_file)
    [[ -f "$file" ]] || return 1
    while read -r role lport lpid lgen; do
        if [[ "$lport" == "$port" ]]; then
            out="$out$role $lpid $lgen"$'\n'
        fi
    done <"$file"
    [[ -n "$out" ]] || return 1
    printf '%s' "$out"
    return 0
}

cpo_ready_owned() {
    # Is the LISTEN socket on port $1 owned by the process this run is waiting
    # for?
    #   rc 0 = yes: a pid this run started, and — on a port an auxiliary
    #          listener is registered on — that listener was started after the
    #          last non-auxiliary process, so it is still the listener this
    #          gate is for.
    #   rc 1 = nobody is listening yet; the caller keeps polling.
    #   rc 2 = cannot tell (no lsof and no ss); the caller fails closed.
    #   rc 3 = somebody else's socket answers (a foreign process, or a listener
    #          this run started that a later launch has superseded). A
    #          diagnostic naming the port and the pid goes to stderr.
    local port="$1"
    local owners="" rc=0 pid foreign="" ours=0
    local aux_lines="" expected_gen="${AUX_LAUNCH_GEN:-0}"
    owners=$(cpo_listen_owner "$port") || rc=$?
    case $rc in
        2) return 2 ;;
        1) return 1 ;;
    esac
    while read -r pid; do
        [[ -n "$pid" ]] || continue
        if cpo_pid_tracked "$pid"; then
            ours=1
        else
            foreign="$foreign $pid"
        fi
    done <<<"$owners"
    if [[ -n "$foreign" ]]; then
        printf 'ERROR: compat-port-ownership: port %s is held by pid%s, which this run did not start — a foreign listener answers this gate\n' \
            "$port" "$foreign" >&2
        return 3
    fi
    (( ours == 1 )) || return 3
    if aux_lines=$(cpo_listener_roles "$port"); then
        # A registered auxiliary listener holds this port: it may own it only
        # while nothing non-auxiliary has been launched since it started. Read
        # the values inside the loop — `read` clears its variables when it hits
        # EOF, so a message printed after the loop would name empty variables.
        local aux_role aux_pid aux_gen
        while read -r aux_role aux_pid aux_gen; do
            [[ -n "$aux_pid" ]] || continue
            if [[ "$aux_gen" == "$expected_gen" ]]; then
                return 0
            fi
            printf 'ERROR: compat-port-ownership: port %s is held by the %s listener this run started (pid %s), but a process launched after it (generation %s) was meant to take this port — the scenario gave two listeners the same port\n' \
                "$port" "$aux_role" "$aux_pid" "$expected_gen" >&2
            return 3
        done <<<"$aux_lines"
        printf 'ERROR: compat-port-ownership: port %s: listener ledger entry has no usable pid; refusing to call it ready\n' \
            "$port" >&2
        return 3
    fi
    return 0
}

cpo_wait_ready() {
    # Poll `cpo_ready_owned` for at most $2 seconds. rc 0 = ready, 1 = never
    # became ready, 2 = cannot tell, 3 = not ours.
    #
    # The poll count is parsed out of the timeout string rather than computed as
    # `$(( timeout * 10 ))`: bash has no float arithmetic, so a fractional
    # timeout made that expansion a syntax error, which fails the assignment and
    # aborts a `set -e` caller instead of polling. Whole seconds and one
    # fractional digit are read; anything else falls back to the 10 s default.
    local port="$1" timeout="${2:-10}" i=0 n rc=0
    local _whole="${timeout%%.*}" _frac=""
    case "$timeout" in
        *.*) _frac="${timeout#*.}" ;;
    esac
    [[ "$_whole" =~ ^[0-9]+$ ]] || _whole=10
    n=$(( _whole * 10 ))
    case "$_frac" in
        [0-9]*) n=$(( n + ${_frac:0:1} )) ;;
    esac
    (( n > 0 )) || n=1
    while (( i < n )); do
        rc=0
        cpo_ready_owned "$port" || rc=$?
        case $rc in
            0) return 0 ;;
            1) : ;;
            *) return "$rc" ;;
        esac
        sleep 0.1
        i=$(( i + 1 ))
    done
    return 1
}

cpo_wait_port_ready() {
    # The readiness gate `wait_for_port` / `wait_for_port_safe` use.
    # rc 0 = the port is ready; rc 1 = it never was, and the reason (a foreign
    # socket, no probe at all, or no owner) is on stderr. rc 2 ("cannot tell")
    # is a failure, never a pass.
    local port="$1" timeout="${2:-10}" rc=0
    cpo_wait_ready "$port" "$timeout" || rc=$?
    case $rc in
        0) return 0 ;;
        2)
            printf 'ERROR: compat-port-ownership: port %s: neither lsof nor ss is installed, so this gate cannot tell whose socket answered; refusing to report it ready\n' \
                "$port" >&2
            return 1
            ;;
        3) return 1 ;;
        *)
            printf 'ERROR: compat-port-ownership: port %s never had a LISTEN socket owned by this run (waited %ss)\n' \
                "$port" "$timeout" >&2
            return 1
            ;;
    esac
}
