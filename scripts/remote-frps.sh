#!/usr/bin/env bash
# =============================================================================
# Remote frps lifecycle management for XTCP CI tests.
# Manages frps (Rust or Go) on a VPS with a public IP.
#
# Usage:
#   bash scripts/remote-frps.sh start  <impl> <host> <port> <token> <ssh-key> [shard]
#   bash scripts/remote-frps.sh stop   <host> <ssh-key> [shard]
#   bash scripts/remote-frps.sh status <host> <ssh-key> [shard]
#
# <impl>: "rust" or "go"
# <shard>: optional numeric shard index for CI matrix isolation.
#          When set, uses /tmp/frp-xtcp-shard-{shard}/ instead of mktemp -d.
# VPS user from XTCP_VPS_USER env var (default: frp-test)
#
# Port conflict handling: start tries requested port, falls back to
# scanning port..port+100 for first available. Echoes actual port used.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VPS_USER="${XTCP_VPS_USER:-frp-test}"
GO_FRP_VERSION="${GO_FRP_VERSION:-0.69.1}"
# VPS target is always linux/amd64
GO_FRP_ARCH="linux_amd64"
REMOTE_DIR="/tmp/frp-xtcp-test"
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=2 -o ConnectionAttempts=1 -o ControlMaster=auto -o ControlPath=/tmp/frp-ssh-ctl-%h-%r -o ControlPersist=120"
SSH_TIMEOUT=30  # hard timeout per SSH invocation (prevents ControlMaster hang)

# Wrap SSH with timeout to prevent hangs from broken ControlMaster
ssh_t() {
    timeout "$SSH_TIMEOUT" ssh $SSH_OPTS "$@"
}

usage() {
    cat >&2 <<EOF
Usage:
  $0 start  <impl> <host> <port> <token> <ssh-key> [shard]
  $0 stop   <host> <ssh-key> [shard]
  $0 status <host> <ssh-key> [shard]

<impl>: "rust" or "go"
<shard>: optional numeric shard index (0-3) for CI matrix isolation
VPS user: \$XTCP_VPS_USER (default: $VPS_USER)

Start echoes the actual port used as its final stdout line.
Port conflict: scans port..port+100 for first available port.
EOF
    exit 1
}

die() { echo "ERROR: $*" >&2; exit 1; }

# =============================================================================
# Port management (remote checks via SSH)
# =============================================================================

# Scan port..port+100 on VPS, return first available port number
find_available_port() {
    local host="$1" port="$2" ssh_key="$3"
    local max=$((port + 100))

    local p
    for p in $(seq "$port" "$max"); do
        local in_use
        in_use=$(ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
            "ss -tlnp 2>/dev/null | grep ':${p}\b' || true" 2>/dev/null) || true
        if [[ -z "$in_use" ]]; then
            echo "$p"
            return 0
        fi
    done
    die "no available port in range $port-$max on $host"
}

# Wait for frps to be listening on the given port
wait_remote_port() {
    local host="$1" port="$2" ssh_key="$3" remote_dir="${4:-}"
    local max_attempts=30

    local i
    echo "DBG: wait_remote_port host=$host port=$port max_attempts=$max_attempts remote_dir=$remote_dir" >&2
    for i in $(seq 1 "$max_attempts"); do
        local listening ssh_rc
        listening=$(ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
            "ss -tlnp 2>/dev/null | grep ':${port}\b' || true" 2>/dev/null) || true
        ssh_rc=$?
        if [[ $ssh_rc -ne 0 ]]; then
            echo "WARNING: SSH to $host failed (exit=$ssh_rc) during port check $i/$max_attempts" >&2
        fi
        if [[ -n "$listening" ]]; then
            return 0
        fi
        sleep 1
    done

    # Fetch frps log to help diagnose why it didn't start
    local frps_log="(unavailable)"
    if [[ -n "$remote_dir" ]]; then
        frps_log=$(ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
            "cat '$remote_dir/frps.log' 2>/dev/null || echo '(no log)'" 2>/dev/null) || true
    fi
    die "frps on $host:$port did not become ready within ${max_attempts}s. frps.log: $frps_log"
}

# =============================================================================
# Config generation
# =============================================================================

# Write frps config to a temp file, return path via stdout
write_frps_config() {
    local impl="$1" port="$2" token="$3"
    local out="/tmp/frps-remote-config-$$.toml"

    if [[ "$impl" == "go" ]]; then
        # Go frp uses camelCase TOML keys
        cat > "$out" <<TOML
bindAddr = "0.0.0.0"
bindPort = $port
auth.method = "token"
auth.token = "$token"
log.to = "./frps.log"
log.level = "debug"
transport.tcpMux = false
TOML
    else
        # Rust frp-rs uses snake_case TOML keys
        cat > "$out" <<TOML
bind_addr = "0.0.0.0"
bind_port = $port

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false
TOML
    fi
    echo "$out"
}

# =============================================================================
# Commands
# =============================================================================

cmd_start() {
    local impl="$1" host="$2" port="$3" token="$4" ssh_key="$5" shard="${6:-}"

    # --- Validation ---
    if [[ "$impl" != "rust" && "$impl" != "go" ]]; then
        die "invalid impl '$impl': must be 'rust' or 'go'"
    fi
    if [[ ! -f "$ssh_key" ]]; then
        die "SSH key not found (check XTCP_VPS_SSH_KEY)"
    fi

    # --- Determine remote directory and clean up stale state ---
    local remote_dir
    if [[ -n "$shard" ]]; then
        # CI matrix isolation: deterministic per-shard directory.
        # Only touches THIS shard's process and directory.
        remote_dir="/tmp/frp-xtcp-shard-${shard}"
        ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
            "if [ -f '$remote_dir/frps.pid' ]; then \
               pid=\$(cat '$remote_dir/frps.pid' 2>/dev/null); \
               if [ -n \"\$pid\" ]; then \
                 kill -0 \"\$pid\" 2>/dev/null && kill \"\$pid\" 2>/dev/null || true; \
                 sleep 0.3; \
                 kill -0 \"\$pid\" 2>/dev/null && kill -9 \"\$pid\" 2>/dev/null || true; \
               fi; \
             fi; \
                          for p in \$(seq $((17000 + shard * 100)) $((17000 + shard * 100 + 99))); do \
                            fpid=\$(ss -tlnp 2>/dev/null | grep \":\${p}\b\" | grep -o 'pid=[0-9]*' | cut -d= -f2); \
                            if [ -n "\$fpid" ]; then kill "\$fpid" 2>/dev/null || true; fi; \
                          done; \
             rm -rf '$remote_dir'; \
             mkdir -p '$remote_dir'" 2>/dev/null || true
    else
        # Backward compat (single runner): global pkill + mktemp
        ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
            "pkill -f 'frps -c frps.toml' 2>/dev/null; \
             for d in /tmp/frp-xtcp-?????? /tmp/frp-xtcp-test; do \
                 if [ -d \"\$d\" ]; then rm -rf \"\$d\" 2>/dev/null; fi; \
             done; \
             rm -f /tmp/.frp-xtcp-dir 2>/dev/null" 2>/dev/null || true
    fi

    # --- Find available port (dies if none in range) ---
    local actual_port
    echo "DBG: find_available_port host=$host port=$port" >&2
    actual_port=$(find_available_port "$host" "$port" "$ssh_key")
    echo "DBG: found port=$actual_port" >&2

    # --- Determine binary path ---
    local binary_path
    if [[ "$impl" == "rust" ]]; then
        binary_path="$PROJECT_DIR/target/release/frps"
    else
        binary_path="${GO_FRP_DIR:-/tmp/frp_${GO_FRP_VERSION}_${GO_FRP_ARCH}}/frps"
    fi

    if [[ ! -f "$binary_path" ]]; then
        die "frps binary not found: $binary_path"
    fi

    # --- Generate config ---
    local config_path
    config_path=$(write_frps_config "$impl" "$actual_port" "$token")

    # --- Ensure remote directory exists ---
    if [[ -z "$shard" ]]; then
        # Backward compat: mktemp creates unique writable dir owned by frp-test
        local mkdir_err
        remote_dir=$(ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
            "mktemp -d /tmp/frp-xtcp-XXXXXX" 2>&1) || {
            rm -f "$config_path"
            die "failed to create remote directory on $host: $remote_dir"
        }
        # Store path for stop/status to find later
        ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
            "echo '$remote_dir' > /tmp/.frp-xtcp-dir" 2>/dev/null || true
    fi
    # (if shard is set, remote_dir was already set and dir was created in pre-flight)

    # --- Upload binary and config ---
    local scp_opts="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ControlPath=/tmp/frp-ssh-ctl-%h-%r"
    local scp_err
    scp_err=$(scp $scp_opts -i "$ssh_key" "$binary_path" "${VPS_USER}@${host}:${remote_dir}/frps" 2>&1 1>/dev/null) || {
        rm -f "$config_path"
        die "failed to upload frps binary to $host: $scp_err"
    }
    scp_err=$(scp $scp_opts -i "$ssh_key" "$config_path" "${VPS_USER}@${host}:${remote_dir}/frps.toml" 2>&1 1>/dev/null) || {
        rm -f "$config_path"
        die "failed to upload frps config to $host: $scp_err"
    }

    # Clean up local config
    rm -f "$config_path"

    # --- Start frps on VPS ---
    # Redirect all fds to detach from SSH session; nohup ensures survival
    local start_output start_rc
    start_output=$(ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
        "cd $remote_dir && chmod +x frps && nohup ./frps -c frps.toml > frps.log 2>&1 < /dev/null & echo \$! > frps.pid" 2>&1)
    start_rc=$?
    if [[ $start_rc -ne 0 ]]; then
        die "failed to start frps on $host (exit=$start_rc): $start_output"
    fi

    # Quick liveness check: if frps exits immediately (config parse error, etc.),
    # we can fail fast with the log instead of waiting 30s for wait_remote_port.
    sleep 2
    echo "DBG: checking liveness of frps on $host:$actual_port dir=$remote_dir" >&2
    local alive_check
    alive_check=$(ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
        "pid=\$(cat '$remote_dir/frps.pid' 2>/dev/null); if [ -n \"\$pid\" ] && kill -0 \"\$pid\" 2>/dev/null; then echo alive; else echo dead; fi" 2>/dev/null) || true
    if [[ "$alive_check" == "dead" ]]; then
        local early_log
        early_log=$(ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
            "cat '$remote_dir/frps.log' 2>/dev/null || echo '(no log)'" 2>/dev/null) || true
        die "frps on $host exited immediately after start. frps.log: $early_log"
    fi
    echo "DBG: alive check passed (result='$alive_check'), entering wait_remote_port" >&2

    # --- Wait for frps to be ready ---
    wait_remote_port "$host" "$actual_port" "$ssh_key" "$remote_dir"

    # Echo actual port (MUST be last line of stdout for compat-test.sh integration)
    echo "$actual_port"
}

cmd_stop() {
    local host="$1" ssh_key="$2" shard="${3:-}"

    if [[ ! -f "$ssh_key" ]]; then
        die "SSH key not found (check XTCP_VPS_SSH_KEY)"
    fi

    local result
    if [[ -n "$shard" ]]; then
        # CI matrix isolation: only kill this shard's frps, only clean its dir
        local base_port=$((17000 + shard * 100))
        local remote_dir="/tmp/frp-xtcp-shard-${shard}"
        result=$(ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
            "if [ -f '$remote_dir/frps.pid' ]; then \
               pid=\$(cat '$remote_dir/frps.pid' 2>/dev/null); \
               if [ -n \"\$pid\" ]; then \
                 kill -0 \"\$pid\" 2>/dev/null && kill \"\$pid\" 2>/dev/null || true; \
                 sleep 0.3; \
                 kill -0 \"\$pid\" 2>/dev/null && kill -9 \"\$pid\" 2>/dev/null || true; \
               fi; \
             fi; \
                          for p in \$(seq ${base_port} $((base_port + 99))); do \
                            fpid=\$(ss -tlnp 2>/dev/null | grep \":\${p}\b\" | grep -o 'pid=[0-9]*' | cut -d= -f2); \
                            if [ -n "\$fpid" ]; then \
                              kill "\$fpid" 2>/dev/null || true; \
                            fi; \
                          done; \
             rm -rf '$remote_dir'; \
             echo ok" 2>&1) || {
            echo "WARNING: remote stop on $host failed: $result" >&2
            return 1
        }
    else
        # Backward compat: kill all frps, clean all mktemp dirs
        result=$(ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
            "pkill -f 'frps -c frps.toml' 2>/dev/null; \
             for d in /tmp/frp-xtcp-?????? /tmp/frp-xtcp-test; do \
                 if [ -d \"\$d\" ]; then rm -rf \"\$d\" 2>/dev/null; fi; \
             done; \
             rm -f /tmp/.frp-xtcp-dir 2>/dev/null; \
             echo ok" 2>&1) || {
            echo "WARNING: remote stop on $host failed: $result" >&2
            return 1
        }
    fi
    echo "stopped"
}

cmd_status() {
    local host="$1" ssh_key="$2" shard="${3:-}"

    if [[ ! -f "$ssh_key" ]]; then
        die "SSH key not found (check XTCP_VPS_SSH_KEY)"
    fi

    if [[ -n "$shard" ]]; then
        # CI matrix isolation: only check this shard's directory
        local remote_dir="/tmp/frp-xtcp-shard-${shard}"
        local running
        running=$(ssh_t -i "$ssh_key" "${VPS_USER}@${host}" \
            "if [ -f '$remote_dir/frps.pid' ]; then \
               pid=\$(cat '$remote_dir/frps.pid'); \
               if kill -0 \"\$pid\" 2>/dev/null; then \
                 echo 'running (pid='\$pid', dir=$remote_dir)'; \
               else \
                 echo 'stopped (stale pid='\$pid', dir=$remote_dir)'; \
               fi; \
             else \
               echo 'stopped (no pid file in $remote_dir)'; \
             fi" 2>/dev/null) || running="unknown (ssh failed)"
        echo "$running"
        return
    fi

    # Backward compat: check all frp-xtcp temp dirs
    local running
    running=$(ssh_t -i "$ssh_key" "${VPS_USER}@${host}" "bash -s" 2>/dev/null <<'REMOTE_SCRIPT'
# Check all frp-xtcp temp dirs
found=0
for d in /tmp/frp-xtcp-??????; do
    if [[ -d "$d" ]]; then
        found=1
        PID_FILE="$d/frps.pid"
        if [[ -f "$PID_FILE" ]]; then
            pid=$(cat "$PID_FILE")
            if kill -0 "$pid" 2>/dev/null; then
                echo "running (pid=$pid, dir=$d)"
                exit 0
            else
                echo "stopped (stale pid=$pid, dir=$d)"
            fi
        fi
    fi
done
# Also check legacy dir
if [[ -f "/tmp/frp-xtcp-test/frps.pid" ]]; then
    pid=$(cat "/tmp/frp-xtcp-test/frps.pid")
    if kill -0 "$pid" 2>/dev/null; then
        echo "running (pid=$pid)"
        exit 0
    fi
fi
if [[ $found -eq 1 ]]; then
    echo "stopped (stale)"
else
    if pgrep -f "frps -c frps.toml" > /dev/null 2>&1; then
        echo "running (no pid file)"
    else
        echo "stopped"
    fi
fi
REMOTE_SCRIPT
) || running="unknown (ssh failed)"

    echo "$running"
}

# =============================================================================
# Main dispatch
# =============================================================================

case "${1:-}" in
    start)
        if [[ $# -lt 6 || $# -gt 7 ]]; then
            echo "ERROR: start requires 5-6 args: impl host port token ssh-key [shard]" >&2
            usage
        fi
        cmd_start "$2" "$3" "$4" "$5" "$6" "${7:-}"
        ;;
    stop)
        if [[ $# -lt 3 || $# -gt 4 ]]; then
            echo "ERROR: stop requires 2-3 args: host ssh-key [shard]" >&2
            usage
        fi
        cmd_stop "$2" "$3" "${4:-}"
        ;;
    status)
        if [[ $# -lt 3 || $# -gt 4 ]]; then
            echo "ERROR: status requires 2-3 args: host ssh-key [shard]" >&2
            usage
        fi
        cmd_status "$2" "$3" "${4:-}"
        ;;
    *)
        usage
        ;;
esac
