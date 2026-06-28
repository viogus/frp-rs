#!/usr/bin/env bash
# =============================================================================
# Remote frps lifecycle management for XTCP CI tests.
# Manages frps (Rust or Go) on a VPS with a public IP.
#
# Usage:
#   bash scripts/remote-frps.sh start  <impl> <host> <port> <token> <ssh-key>
#   bash scripts/remote-frps.sh stop   <host> <ssh-key>
#   bash scripts/remote-frps.sh status <host> <ssh-key>
#
# <impl>: "rust" or "go"
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
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ControlMaster=auto -o ControlPath=/tmp/frp-ssh-ctl-%h-%r -o ControlPersist=120"

usage() {
    cat >&2 <<EOF
Usage:
  $0 start  <impl> <host> <port> <token> <ssh-key>
  $0 stop   <host> <ssh-key>
  $0 status <host> <ssh-key>

<impl>: "rust" or "go"
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
        in_use=$(ssh $SSH_OPTS -i "$ssh_key" "${VPS_USER}@${host}" \
            "ss -tlnp 2>/dev/null | grep ':${p}\b' || true" 2>/dev/null)
        if [[ -z "$in_use" ]]; then
            echo "$p"
            return 0
        fi
    done
    die "no available port in range $port-$max on $host"
}

# Wait for frps to be listening on the given port
wait_remote_port() {
    local host="$1" port="$2" ssh_key="$3"
    local max_attempts=30

    local i
    for i in $(seq 1 "$max_attempts"); do
        local listening
        listening=$(ssh $SSH_OPTS -i "$ssh_key" "${VPS_USER}@${host}" \
            "ss -tlnp 2>/dev/null | grep ':${port}\b' || true" 2>/dev/null)
        if [[ -n "$listening" ]]; then
            return 0
        fi
        sleep 1
    done
    die "frps on $host:$port did not become ready within ${max_attempts}s"
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
log.to = "$REMOTE_DIR/frps.log"
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
    local impl="$1" host="$2" port="$3" token="$4" ssh_key="$5"

    # --- Validation ---
    if [[ "$impl" != "rust" && "$impl" != "go" ]]; then
        die "invalid impl '$impl': must be 'rust' or 'go'"
    fi
    if [[ ! -f "$ssh_key" ]]; then
        die "SSH key not found (check XTCP_VPS_SSH_KEY)"
    fi

    # --- Find available port (dies if none in range) ---
    local actual_port
    actual_port=$(find_available_port "$host" "$port" "$ssh_key")

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
    local ssh_err
    ssh_err=$(ssh $SSH_OPTS -i "$ssh_key" "${VPS_USER}@${host}" "mkdir -p $REMOTE_DIR" 2>&1 1>/dev/null) || {
        rm -f "$config_path"
        die "failed to create remote directory $REMOTE_DIR on $host: $ssh_err"
    }

    # --- Upload binary and config ---
    local scp_opts="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ControlPath=/tmp/frp-ssh-ctl-%h-%r"
    local scp_err
    scp_err=$(scp $scp_opts -i "$ssh_key" "$binary_path" "${VPS_USER}@${host}:${REMOTE_DIR}/frps" 2>&1 1>/dev/null) || {
        rm -f "$config_path"
        die "failed to upload frps binary to $host: $scp_err"
    }
    scp_err=$(scp $scp_opts -i "$ssh_key" "$config_path" "${VPS_USER}@${host}:${REMOTE_DIR}/frps.toml" 2>&1 1>/dev/null) || {
        rm -f "$config_path"
        die "failed to upload frps config to $host: $scp_err"
    }

    # Clean up local config
    rm -f "$config_path"

    # --- Start frps on VPS ---
    # Redirect all fds to detach from SSH session; nohup ensures survival
    ssh_err=$(ssh $SSH_OPTS -i "$ssh_key" "${VPS_USER}@${host}" \
        "cd $REMOTE_DIR && chmod +x frps && nohup ./frps -c frps.toml > frps.log 2>&1 < /dev/null & echo \$! > frps.pid" 2>&1 1>/dev/null) || {
        die "failed to start frps on $host: $ssh_err"
    }

    # --- Wait for frps to be ready ---
    wait_remote_port "$host" "$actual_port" "$ssh_key"

    # Echo actual port (MUST be last line of stdout for compat-test.sh integration)
    echo "$actual_port"
}

cmd_stop() {
    local host="$1" ssh_key="$2"

    if [[ ! -f "$ssh_key" ]]; then
        die "SSH key not found (check XTCP_VPS_SSH_KEY)"
    fi

    # Run cleanup script on VPS. Suppress stderr (SSH warnings, kill output).
    # || true ensures we don't fail if the remote dir is already gone.
    ssh $SSH_OPTS -i "$ssh_key" "${VPS_USER}@${host}" "bash -s" 2>/dev/null <<'REMOTE_SCRIPT' || true
set -euo pipefail
PID_FILE="/tmp/frp-xtcp-test/frps.pid"
if [[ -f "$PID_FILE" ]]; then
    pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        # Graceful shutdown: wait up to 10s
        for i in $(seq 1 10); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 1
        done
        # Force kill if still alive
        kill -9 "$pid" 2>/dev/null || true
    fi
fi
# Clean up any straggler frps processes
pkill -f "frps -c frps.toml" 2>/dev/null || true
# Remove remote directory
rm -rf /tmp/frp-xtcp-test 2>/dev/null || true
REMOTE_SCRIPT
    echo "stopped"
}

cmd_status() {
    local host="$1" ssh_key="$2"

    if [[ ! -f "$ssh_key" ]]; then
        die "SSH key not found (check XTCP_VPS_SSH_KEY)"
    fi

    local running
    running=$(ssh $SSH_OPTS -i "$ssh_key" "${VPS_USER}@${host}" "bash -s" 2>/dev/null <<'REMOTE_SCRIPT'
PID_FILE="/tmp/frp-xtcp-test/frps.pid"
if [[ -f "$PID_FILE" ]]; then
    pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
        echo "running (pid=$pid)"
    else
        echo "stopped (stale pid=$pid)"
    fi
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
        [[ $# -eq 6 ]] || {
            echo "ERROR: start requires 5 args: impl host port token ssh-key" >&2
            usage
        }
        cmd_start "$2" "$3" "$4" "$5" "$6"
        ;;
    stop)
        [[ $# -eq 3 ]] || {
            echo "ERROR: stop requires 2 args: host ssh-key" >&2
            usage
        }
        cmd_stop "$2" "$3"
        ;;
    status)
        [[ $# -eq 3 ]] || {
            echo "ERROR: status requires 2 args: host ssh-key" >&2
            usage
        }
        cmd_status "$2" "$3"
        ;;
    *)
        usage
        ;;
esac
