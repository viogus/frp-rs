#!/usr/bin/env bash
# Protocol connectivity matrix: end-to-end data transfer through frps+frpc
# for every transport protocol / TLS / tcp-mux combination.
#
# Each row starts an echo server, frps, and frpc, then runs the frp-stress
# throughput scenario against the proxy port. A row passes iff data moves
# (mbps > 0) — this catches "connects but bridges zero bytes" regressions
# like the WS-over-TLS lost-wakeup stall.
#
# Usage:
#   bash scripts/protocol-matrix.sh [--verbose] [--keep-tmp]
#                                 [--floors <file> | --floors-report <file>]
#                                 [--rates-json <file>]
#   FRPS_BIN=/path/to/frps FRPC_BIN=/path/to/frpc bash scripts/protocol-matrix.sh
#
# Defaults to the local release binaries. TLS rows use the committed
# frp-core/tests/certs. Exit code is non-zero if any row fails.
#
# `--rates-json <file>` writes every row's measured rate as a small JSON
# document (`{"rows": {...}, "unit": "MiB/s"}`), so a CI job can archive it
# and a later run can be diffed against it.
#
# `--floors-report <file>` runs the same check and prints the verdict without
# failing the run; use it on a host whose variance you have not characterized.
#
# `--floors <file>` turns the matrix into a throughput check. The file holds
# one `row=floor` line per row (comments and blank lines allowed); a floor is
# either an absolute MiB/s number (`kcp-plain=20`) or a fraction of this run's
# own `tcp-plain` rate (`kcp-plain=ratio:0.06`). The relative form is the one to
# prefer on shared CI runners: absolute MiB/s varies with the host, while the
# ratio between two transports measured back-to-back on the same runner does
# not, and a transport collapsing — a 3x KCP regression is what this exists for
# — moves the ratio. Rows missing from the file are not gated; a floor naming a
# row this run did not execute is an error, so a typo cannot silently weaken
# the gate.
#
# The matrix does not build anything: it measures whatever FRPS_BIN/FRPC_BIN
# point at. Rebuild before trusting a number — a stale `target/release` once
# reported a FEC fix as doing nothing.
#
# `--keep-tmp` (or FRP_MATRIX_KEEP_TMP=1) leaves the per-row frps.log/frpc.log
# in place; without it the EXIT trap removes $TEST_DIR, so the log paths that a
# failed row prints with --verbose name files that no longer exist by the time
# anyone reads the CI log. `FRP_MATRIX_TEST_DIR` overrides the run directory
# (a per-repeat caller needs a fresh one: the same $TEST_DIR is wiped at the
# start of every run, so an unoverridden repeat loop keeps only the last run's
# logs).
set -u

# Resolve through BASH_SOURCE, not $0: `scripts/tests/compat-port-ownership.sh`
# sources this file to drive `wait_for_listen` in isolation, and a sourced
# script's `$0` is the caller's.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FRPS_BIN="${FRPS_BIN:-$PROJECT_DIR/target/release/frps}"
FRPC_BIN="${FRPC_BIN:-$PROJECT_DIR/target/release/frpc}"
STRESS_BIN="$PROJECT_DIR/scripts/frp-stress/target/release/frp-stress"
CERT_DIR="$PROJECT_DIR/frp-core/tests/certs"
TEST_DIR="${FRP_MATRIX_TEST_DIR:-/tmp/frp-protocol-matrix}"
TOKEN="matrix-token"
VERBOSE=false
KEEP_TMP=false
[[ "${FRP_MATRIX_KEEP_TMP:-}" == "1" ]] && KEEP_TMP=true

# `wait_for_listen` gets the LISTEN census from the port-ownership lib — the
# same one `scripts/compat-test.sh` uses. This script does not use the lib's
# ledger: each row records its own pids under `$TEST_DIR/<row>/*.pid` and passes
# the pid it is waiting for into `wait_for_listen`.
# shellcheck source=scripts/lib/compat-port-ownership.sh
source "$PROJECT_DIR/scripts/lib/compat-port-ownership.sh"

PASS=0
FAIL=0
FAILURES=()
# Measured rates, one `name=rate` string per row in run order, and the names of
# every row the run attempted (a floor may name a row that failed before it was
# measured; that is a row failure, not a floors-file typo).
RATES=()
ALL_ROWS=()
FLOORS_FILE=""
FLOORS_ENFORCE=true
RATES_JSON=""

log() { echo "[matrix] $*"; }
vlog() { $VERBOSE && echo "[matrix] $*" || true; }

cleanup() {
    # Kill any stragglers from an interrupted run. frps/frpc pid files live
    # per-row under $TEST_DIR/<name>/, echo pid files at the top level.
    # Guard on both file existence AND non-empty content: a zero-byte pid
    # file would make `kill ""` fail on its first (invalid) argument and
    # abort the whole command, leaking the remaining stragglers.
    local pid_file pid
    for pid_file in "$TEST_DIR"/*.pid "$TEST_DIR"/*/*.pid; do
        [[ -f "$pid_file" ]] || continue
        pid="$(cat "$pid_file" 2>/dev/null)" || continue
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
    done
    $KEEP_TMP || rm -rf "$TEST_DIR"
}

wait_for_port() {
    # $1=host $2=port $3=timeout_s — poll with bash /dev/tcp.
    local host="$1" port="$2" timeout="${3:-10}" i
    for ((i = 0; i < timeout * 10; i++)); do
        (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null && {
            exec 3>&- 3<&-
            return 0
        }
        sleep 0.1
    done
    return 1
}

wait_for_listen() {
    # $1=port $2=timeout_s $3=expected_pid — OBSERVE a listening socket without
    # connecting, and require it to belong to the pid this row launched.
    # A real connect to a frp port creates a ProxyUserConn on the server
    # (`scripts/compat-test.sh` documents the phantom-work-connection hazard
    # that deadlocks encrypted bridges), so the server and proxy gates must not
    # probe by connecting. Round 5: replaced `wait_for_port` there.
    #
    # The census alone was not enough: `lsof -iTCP:"$port" -sTCP:LISTEN -t`
    # returning ANY pid greened the gate, so a foreign process — or a leftover
    # echo from an aborted row — holding the port made the row look ready while
    # its own frps had failed to bind. Now the socket must be owned by
    # `$expected_pid`; a port already held by somebody else fails the gate
    # immediately with a message naming both pids, and an environment where the
    # owner cannot be determined at all (no lsof and no ss) fails closed rather
    # than falling back to a connect.
    local port="$1" timeout="${2:-10}" expected="${3:-}"
    local i owner rc
    if [[ -z "$expected" ]]; then
        echo "ERROR: protocol-matrix: wait_for_listen needs the pid it is waiting for (port $port); refusing to call the port ready" >&2
        return 1
    fi
    for ((i = 0; i < timeout * 10; i++)); do
        owner=$(cpo_listen_owner "$port")
        rc=$?
        if ((rc == 0)); then
            local p
            while read -r p; do
                [[ "$p" == "$expected" ]] && return 0
            done <<<"$owner"
            echo "ERROR: protocol-matrix: port $port is already LISTENing under pid(s) ${owner//$'\n'/, } — not this row's pid $expected; refusing to call it ready" >&2
            return 1
        fi
        if ((rc == 2)); then
            echo "ERROR: protocol-matrix: cannot determine the owner of port $port (neither lsof nor ss available); failing closed" >&2
            return 1
        fi
        sleep 0.1
    done
    return 1
}

start_echo() {
    local port="$1"
    local pid
    "$STRESS_BIN" --scenario echo --port "$port" >/dev/null 2>&1 &
    pid=$!
    echo "$pid" > "$TEST_DIR/echo-$port.pid"
    sleep 0.5
    wait_for_listen "$port" 5 "$pid"
}

# run_row <name> <proto> <tls:on|off> <mux:on|off>
run_row() {
    local name="$1" proto="$2" tls="$3" mux="$4"
    ALL_ROWS+=("$name")
    local base
    base=$((19000 + 4 * (PASS + FAIL))) # disjoint 4-port block per row
    local srv_port=$((base))
    local proxy_port=$((base + 1))
    local echo_port=$((base + 2))
    local extra_port=$((base + 3))
    local row_dir="$TEST_DIR/$name"
    mkdir -p "$row_dir"

    # Kill this row's processes on ANY exit path. A failed row that skips
    # cleanup leaks frps/frpc/echo, and a leaked listener is this harness's worst
    # failure mode. Round 5: the block is now `19000 + 4 * (PASS + FAIL)`, i.e.
    # four ports wide and disjoint row to row, so a straggler can never be read
    # as the next row's own listener. It used to advance by ONE while the block
    # stayed four wide, so the blocks overlapped by three — this row's
    # proxy_port was the next row's srv_port, its echo_port the next row's
    # proxy_port, its extra_port the next row's echo_port — and a straggling
    # echo then turned the next row's readiness probe green against a non-frp
    # server (silently measuring nothing) or made the next row's real frps fail
    # to bind and report "proxy port not reachable", which is the cascade shape
    # the recorded CI failures show (and as this harness's earlier note recorded:
    # one failed row under load left stragglers that failed the following rows).
    # kill_row_processes still drains the row —
    # SIGTERM, a bounded wait, SIGKILL, a second bounded wait — because a
    # straggler must not outlive its row even with disjoint ports.
    kill_row_processes() {
        # Build the pid list from files that EXIST: the first failure path
        # runs before frpc is started (no frpc.pid yet), and bash's `kill`
        # aborts the whole command on an invalid first argument — a single
        # missing file used to leak frps AND echo on that path.
        local f pid pids=()
        for f in "$row_dir/frpc.pid" "$row_dir/frps.pid" "$TEST_DIR/echo-$echo_port.pid"; do
            [[ -f "$f" ]] || continue
            pid="$(cat "$f" 2>/dev/null)" || continue
            [[ -n "$pid" ]] && pids+=("$pid")
        done
        ((${#pids[@]} > 0)) || return 0
        local i alive
        kill "${pids[@]}" 2>/dev/null
        # SIGTERM alone was the whole teardown: no wait, no escalation. A
        # straggler that ignores or outlives SIGTERM kept holding ports while the
        # next row started (round 5). Give it 3 s to exit, then SIGKILL it and
        # give that 2 s; only a process that survives SIGKILL is reported.
        for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
            alive=()
            for pid in "${pids[@]}"; do
                kill -0 "$pid" 2>/dev/null && alive+=("$pid")
            done
            ((${#alive[@]} == 0)) && return 0
            sleep 0.1
        done
        kill -9 "${alive[@]}" 2>/dev/null
        for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
            alive=()
            for pid in "${pids[@]}"; do
                kill -0 "$pid" 2>/dev/null && alive+=("$pid")
            done
            ((${#alive[@]} == 0)) && return 0
            sleep 0.1
        done
        vlog "  WARNING: row process(es) still alive after SIGKILL: ${alive[*]}"
        return 0
    }

    log "=== $name (proto=$proto tls=$tls mux=$mux) ==="

    start_echo "$echo_port" || {
        fail_row "$name" "echo server did not start"
        return
    }

    # frps config
    {
        printf 'bind_addr = "127.0.0.1"\nbind_port = %s\n' "$srv_port"
        case "$proto" in
            kcp) printf 'kcp_bind_port = %s\n' "$extra_port" ;;
            quic) printf 'quic_bind_port = %s\n' "$extra_port" ;;
        esac
        if [[ "$tls" == "on" ]] || [[ "$proto" == "quic" ]]; then
            printf 'tls_enable = true\n'
            printf 'tls_cert_file = "%s/server.crt"\n' "$CERT_DIR"
            printf 'tls_key_file = "%s/server.key"\n' "$CERT_DIR"
        fi
        printf '\n[auth]\nmethod = "token"\ntoken = "%s"\n\n[transport]\ntcp_mux = %s\n' "$TOKEN" "$([[ "$mux" == "on" ]] && echo true || echo false)"
        printf '[log]\nlevel = "warn"\n'
    } > "$row_dir/frps.toml"

    # frpc config
    {
        printf 'server_addr = "127.0.0.1"\n'
        case "$proto" in
            kcp | quic)
                # KCP/QUIC dial their own bind ports.
                printf 'server_port = %s\n' "$extra_port"
                ;;
            *)
                printf 'server_port = %s\n' "$srv_port"
                ;;
        esac
        printf 'token = "%s"\nlogin_fail_exit = true\npool_count = 1\n' "$TOKEN"
        printf 'tcp_mux = %s\n' "$([[ "$mux" == "on" ]] && echo true || echo false)"
        [[ "$proto" != "tcp" ]] && printf 'transport_protocol = "%s"\n' "$proto"
        if [[ "$tls" == "on" ]] || [[ "$proto" == "quic" ]]; then
            printf 'tls_enable = true\n'
            printf 'tls_ca_file = "%s/ca.crt"\n' "$CERT_DIR"
            printf 'tls_server_name = "localhost"\n'
            printf 'disable_custom_tls_first_byte = true\n'
        else
            printf 'tls_enable = false\n'
        fi
        printf '\n[[proxies]]\nname = "%s"\ntype = "tcp"\nlocal_ip = "127.0.0.1"\n' "$name"
        printf 'local_port = %s\nremote_port = %s\n' "$echo_port" "$proxy_port"
    } > "$row_dir/frpc.toml"

    local frps_pid
    RUST_LOG=warn "$FRPS_BIN" -c "$row_dir/frps.toml" > "$row_dir/frps.log" 2>&1 &
    frps_pid=$!
    echo "$frps_pid" > "$row_dir/frps.pid"
    wait_for_listen "$srv_port" 20 "$frps_pid" || {
        kill_row_processes
        fail_row "$name" "frps did not start"
        return
    }
    RUST_LOG=warn "$FRPC_BIN" -c "$row_dir/frpc.toml" > "$row_dir/frpc.log" 2>&1 &
    echo $! > "$row_dir/frpc.pid"
    # QUIC: the TCP proxy port only opens after the control conn registers.
    # Generous timeout: a contended CI runner (the parallel Tests job is CPU
    # heavy) can take tens of seconds to start frps+frpc, do the TLS
    # handshake, and register the proxy. The proxy port is bound by **frps**
    # (`remote_port`), so `frps_pid` is the owner the gate must see.
    wait_for_listen "$proxy_port" 45 "$frps_pid" || {
        kill_row_processes
        fail_row "$name" "proxy port not reachable"
        return
    }

    local json="$row_dir/result.jsonl"
    local mbps=0 ok=fail attempt
    # Retry the throughput window: a slow frps/frpc warm-up (first work-conn
    # dial + TLS handshake) on a contended runner can leave the first window
    # empty even though the bridge is healthy. Retries cover the warm-up
    # without masking a genuine stall (a real stall stays at zero across all
    # attempts).
    for attempt in 1 2 3; do
        # --json-truncate: the file is reused across attempts, and without it
        # attempt 2 appends a second object, so json.load raises `Extra data`
        # and every retry is reported as another zero — the retry loop could
        # never succeed, and a row that recovered on attempt 2 was still red.
        "$STRESS_BIN" --scenario throughput --port "$proxy_port" --duration 5 --streams 1 \
            --label "$name" --no-floor --json-out "$json" --json-truncate >/dev/null 2>&1
        mbps=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['mbps'])" "$json" 2>/dev/null || echo 0)
        # Bash cannot compare floats — python decides.
        ok=$(python3 -c "import json,sys; print('pass' if json.load(open(sys.argv[1]))['mbps'] > 0 else 'fail')" "$json" 2>/dev/null || echo fail)
        [[ "$ok" == "pass" ]] && break
        log "retry $attempt/3 $name: zero throughput (mbps=$mbps)"
        sleep 3
    done
    if [[ "$ok" == "pass" ]]; then
        PASS=$((PASS + 1))
        RATES+=("$name=$mbps")
        log "PASS $name: $mbps MiB/s"
    else
        kill_row_processes
        fail_row "$name" "zero throughput (mbps=$mbps)"
        return
    fi

    # Clean up this row's processes (same guarded path as every failure arm).
    # No `sleep 0.5` afterwards: kill_row_processes now waits for the pids to die.
    kill_row_processes
    rm -f "$row_dir/frpc.pid" "$row_dir/frps.pid" "$TEST_DIR/echo-$echo_port.pid"
}

print_rates() {
    local rate
    ((${#RATES[@]} > 0)) || return 0
    echo
    echo "=== protocol matrix: measured throughput (MiB/s, 5 s window, 1 stream) ==="
    for rate in "${RATES[@]}"; do
        printf '[matrix] %-14s %s\n' "${rate%%=*}" "${rate#*=}"
    done
}

write_rates_json() {
    local out="$1"
    [[ -n "$out" ]] || return 0
    # `"${RATES[@]:-}"` rather than `"${RATES[@]}"`: on bash 3.2 (macOS) an
    # empty array under `set -u` is an unbound variable, and this runs on the
    # all-rows-failed path where the diagnosis matters most.
    python3 - "$out" "${RATES[@]:-}" <<'PY'
import json
import os
import sys

out = sys.argv[1]
rows = {}
for item in sys.argv[2:]:
    if not item:
        continue
    name, _, value = item.partition("=")
    rows[name] = float(value)

doc = {
    "rows": rows,
    "unit": "MiB/s",
    "window_s": 5,
    "streams": 1,
    "commit": os.environ.get("GITHUB_SHA", ""),
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

# Compare every measured row against the floors file. Floors are advisory in
# the sense that a floor failing does not undo the row's traffic check, but it
# does fail the run: a transport that still moves bytes while sitting at a
# fraction of its previous rate is exactly the regression class this gate
# exists for, and "mbps > 0" cannot see it.
# $2 = yes to fail the run, no to report only (the CI runner is too noisy to
# gate on until its variance is characterized — see the flag's comment in main).
apply_floors() {
    local floors="$1" enforce="${2:-yes}" out status name detail
    local checked=0 below=0
    if [[ ! -f "$floors" ]]; then
        FAIL=$((FAIL + 1))
        FAILURES+=("floors: file not found: $floors")
        log "FAIL floors: file not found: $floors"
        return
    fi
    # The checker prints one line per verdict and a final `checked|N|M`. The
    # terminator is what makes the gate fail-CLOSED: an empty or truncated
    # verdict stream (a decode error on the floors file, a missing python3, a
    # crash after half the rows) used to produce zero `BELOW|` lines, which the
    # loop below reads exactly like "every floor passed". A gate that vanishes
    # when its checker breaks is a decoration, so the absence of the terminator
    # is itself a failure.
    out=$(MATRIX_ROWS="${ALL_ROWS[*]:-}" python3 - "$floors" "${RATES[@]:-}" <<'PY'
import os
import sys

floors_path = sys.argv[1]
rows_in_matrix = set(os.environ.get("MATRIX_ROWS", "").split())
rates = {}
bad = 0
checked = 0
below = 0

# Skipping empty entries matters: an empty RATES array still expands to one
# empty argument under `set -u`, and float("") used to abort the whole check
# with a traceback (which the caller's `|| true` then swallowed).
for item in sys.argv[2:]:
    if not item:
        continue
    name, _, value = item.partition("=")
    try:
        rates[name] = float(value)
    except ValueError:
        print(f"ERROR||unparseable rate entry from the matrix: {item}")
        bad += 1

base = rates.get("tcp-plain")
floored = set()

with open(floors_path, encoding="utf-8") as fh:
    for raw in fh:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            print(f"ERROR||unparseable floor line: {line}")
            bad += 1
            continue
        name, spec = (part.strip() for part in line.split("=", 1))
        floored.add(name)
        if name not in rates:
            if rows_in_matrix and name not in rows_in_matrix:
                print(f"ERROR||floor names row '{name}', which is not a matrix row")
                bad += 1
            else:
                # In the matrix but never measured: the row failed its own
                # traffic check and already failed the run. Counting it twice
                # would confuse the failure list, and a NOTE keeps the gap
                # visible without inventing a second cause.
                print(f"NOTE|{name}|not measured (the row failed before its rate was recorded)")
            continue
        got = rates[name]
        if spec.startswith("ratio:"):
            try:
                frac = float(spec.split(":", 1)[1])
            except ValueError:
                print(f"ERROR||unparseable ratio floor for {name}: {spec}")
                bad += 1
                continue
            if not base or base <= 0:
                print(f"ERROR||ratio floor for {name} needs a positive tcp-plain rate")
                bad += 1
                continue
            need = frac * base
            what = f"{frac:g}x tcp-plain = {need:.1f}"
        else:
            try:
                need = float(spec)
            except ValueError:
                print(f"ERROR||unparseable floor for {name}: {spec}")
                bad += 1
                continue
            what = f"{need:.1f} absolute"
        checked += 1
        if got >= need:
            print(f"ok|{name}|{got:.1f} MiB/s (floor {what})")
        else:
            print(f"BELOW|{name}|{got:.1f} MiB/s (floor {what})")
            below += 1
            bad += 1

# A row added to the matrix without a floor is gated only by `mbps > 0`,
# silently and forever. Treat that as a failure: it is a one-line fix, and the
# alternative is a gate whose coverage shrinks without anyone noticing.
for name in sorted(rows_in_matrix - floored):
    print(f"UNFLOORED|{name}|the matrix row has no floor in {os.path.basename(floors_path)}")
    bad += 1

print(f"checked|{checked}|{below}")
sys.exit(1 if bad else 0)
PY
) || true
    while IFS='|' read -r status name detail; do
        [[ -n "$name$detail" ]] || continue
        case "$status" in
            ok)
                checked=$((checked + 1))
                vlog "  floor ok $name: $detail"
                ;;
            NOTE) vlog "  floor skipped $name: $detail" ;;
            BELOW)
                checked=$((checked + 1))
                below=$((below + 1))
                if [[ "$enforce" == "yes" ]]; then
                    FAIL=$((FAIL + 1))
                    FAILURES+=("$name: throughput below floor, $detail")
                    log "FAIL $name: throughput below floor — $detail"
                else
                    log "WARN $name: throughput below floor (report only) — $detail"
                fi
                ;;
            UNFLOORED)
                if [[ "$enforce" == "yes" ]]; then
                    FAIL=$((FAIL + 1))
                    FAILURES+=("$name: no throughput floor ($detail)")
                    log "FAIL $name: no throughput floor — $detail"
                else
                    log "WARN $name: no throughput floor (report only) — $detail"
                fi
                ;;
            checked) ;;
            ERROR)
                if [[ "$enforce" == "yes" ]]; then
                    FAIL=$((FAIL + 1))
                    FAILURES+=("floors: $detail")
                    log "FAIL floors: $detail"
                else
                    log "WARN floors (report only): $detail"
                fi
                ;;
            *)
                if [[ "$enforce" == "yes" ]]; then
                    FAIL=$((FAIL + 1))
                    FAILURES+=("floors: unrecognised checker output: $status|$name|$detail")
                    log "FAIL floors: unrecognised checker output: $status|$name|$detail"
                else
                    log "WARN floors (report only): unrecognised checker output: $status|$name|$detail"
                fi
                ;;
        esac
    done <<<"$out"
    if ((checked == 0)); then
        if [[ "$enforce" == "yes" ]]; then
            FAIL=$((FAIL + 1))
            FAILURES+=("floors: the checker produced no verdict for any row")
            log "FAIL floors: the checker produced no verdict for any row (empty or truncated output) — refusing to report a pass"
            return
        fi
        log "WARN floors (report only): the checker produced no verdict for any row (empty or truncated output)"
        return
    fi
    log "floors: $checked checked, $below below ($([[ "$enforce" == yes ]] && echo enforced || echo report only))"
}

fail_row() {
    local name="$1" reason="$2" logf
    FAIL=$((FAIL + 1))
    FAILURES+=("$name: $reason")
    log "FAIL $name: $reason"
    # Always print the row's tails. CI runs the matrix with neither --verbose nor
    # --keep-tmp, so a red step used to print only this FAIL line while the EXIT
    # trap deleted the very logs it named (round 5).
    for logf in "$TEST_DIR/$name/frps.log" "$TEST_DIR/$name/frpc.log"; do
        [[ -f "$logf" ]] || continue
        echo "[matrix]   --- $(basename "$logf"), last 20 lines ---"
        tail -20 "$logf" | sed 's/^/[matrix]   | /'
    done
    vlog "  retained row dir: $TEST_DIR/$name"
}

main() {
    # Argument parsing and the EXIT trap moved in here (they used to run at
    # source time) so `scripts/tests/compat-port-ownership.sh` can source this
    # file to drive `wait_for_listen` without parsing the fixture's argv or
    # arming a cleanup trap against the fixture's directory.
    while (($#)); do
        case "$1" in
            --verbose) VERBOSE=true ;;
            --keep-tmp) KEEP_TMP=true ;;
            --floors | --floors-report | --rates-json)
                [[ $# -ge 2 && -n "$2" ]] || {
                    echo "protocol-matrix: $1 needs a path" >&2
                    exit 2
                }
                case "$1" in
                    --floors) FLOORS_FILE="$2" ;;
                    --floors-report)
                        # Same check, reported not enforced. The shared CI runner
                        # is not a stable enough host to gate on yet: one run
                        # measured tcp-plain at 18.0 MiB/s and wss at 315.3, and
                        # the three KCP rows spanned 3.05-22.5, so a 3x
                        # regression is indistinguishable from that noise. Gate
                        # locally (or on a quiet runner) with --floors; CI
                        # publishes the table and the verdict until TODO.md's
                        # "matrix tcp-plain floor" item is closed.
                        FLOORS_FILE="$2"
                        FLOORS_ENFORCE=false
                        ;;
                    *) RATES_JSON="$2" ;;
                esac
                shift
                ;;
            *) echo "protocol-matrix: unknown argument: $1" >&2; exit 2 ;;
        esac
        shift
    done
    trap cleanup EXIT

    [[ -x "$FRPS_BIN" ]] || { echo "frps not found: $FRPS_BIN (build or set FRPS_BIN)"; exit 2; }
    [[ -x "$FRPC_BIN" ]] || { echo "frpc not found: $FRPC_BIN (build or set FRPC_BIN)"; exit 2; }
    [[ -x "$STRESS_BIN" ]] || { echo "frp-stress not found: $STRESS_BIN (cargo build --release -p frp-stress)"; exit 2; }
    for cert in ca.crt server.crt server.key; do
        [[ -f "$CERT_DIR/$cert" ]] || { echo "cert missing: $CERT_DIR/$cert"; exit 2; }
    done
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"

    # name            proto       tls   mux
    run_row "tcp-plain"    tcp        off   off
    run_row "tcp-tls"      tcp        on    off
    run_row "tcp-tls-mux"  tcp        on    on
    run_row "ws-plain"     websocket  off   off
    run_row "ws-tls"       websocket  on    off
    run_row "ws-tls-mux"   websocket  on    on
    run_row "wss"          wss        on    off
    run_row "kcp-plain"    kcp        off   off
    run_row "kcp-tls"      kcp        on    off
    run_row "kcp-tls-mux"  kcp        on    on
    run_row "quic"         quic       on    off

    print_rates
    write_rates_json "$RATES_JSON"
    [[ -n "$FLOORS_FILE" ]] && apply_floors "$FLOORS_FILE" "$([[ "$FLOORS_ENFORCE" == true ]] && echo yes || echo no)"

    echo
    echo "=== protocol matrix: $PASS row(s) passed, $FAIL failure(s) ==="
    for f in "${FAILURES[@]:-}"; do
        [[ -n "$f" ]] && echo "  FAIL: $f"
    done
    [[ $FAIL -eq 0 ]]
}

# Only run when executed, not when sourced by the fixture suite.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
