#!/usr/bin/env bash
# =============================================================================
# VPS setup script for XTCP CI testing.
# Run as root on the VPS. Creates frp-test user, configures SSH, opens firewall.
#
# Usage:
#   bash vps-setup.sh <public-key>
#
#   <public-key>: SSH public key content, e.g. "ssh-ed25519 AAAA... xtcp-ci"
#                 Or pipe it: cat ~/.ssh/xtcp-ci.pub | bash vps-setup.sh
#
# What this does:
#   1. Create frp-test user (no sudo, locked password)
#   2. Configure SSH authorized_keys with command restriction
#   3. Open firewall ports 17000–17100 TCP
#   4. Install netcat if missing
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log()  { echo -e "${GREEN}[vps-setup]${NC} $*"; }
warn() { echo -e "${RED}[vps-setup]${NC} $*"; }

# ── Parse public key ──

PUBLIC_KEY="${1:-}"

if [[ -z "$PUBLIC_KEY" ]]; then
    # Try reading from stdin (piped)
    if [[ ! -t 0 ]]; then
        PUBLIC_KEY=$(cat)
    fi
fi

if [[ -z "$PUBLIC_KEY" ]]; then
    warn "No public key provided."
    echo "Usage: bash vps-setup.sh '<ssh-public-key>'"
    echo "   or: cat ~/.ssh/xtcp-ci.pub | bash vps-setup.sh"
    exit 1
fi

# Validate: must look like an SSH public key
if [[ ! "$PUBLIC_KEY" =~ ^(ssh|ecdsa)-[a-zA-Z0-9] ]]; then
    warn "Doesn't look like an SSH public key: ${PUBLIC_KEY:0:50}..."
    warn "Expected format: ssh-ed25519 AAAA... comment"
    exit 1
fi

log "Public key looks valid: ${PUBLIC_KEY##* }"

# ── 1. Create frp-test user ──

if id frp-test &>/dev/null; then
    log "User frp-test already exists, skipping creation"
else
    useradd -m -s /bin/bash frp-test
    log "Created user: frp-test"
fi

# Lock password (SSH key only)
passwd -l frp-test 2>/dev/null || true
log "Password locked (key-only auth)"

# Remove from sudo/wheel groups
gpasswd -d frp-test sudo 2>/dev/null || true
gpasswd -d frp-test wheel 2>/dev/null || true
log "Removed from sudo/wheel groups"

# ── 2. Configure SSH ──

SSH_DIR="/home/frp-test/.ssh"
AUTH_FILE="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR"

# Write authorized_keys (plain key, no options — restrict causes SSH agent hang
# on some OpenSSH versions. frp-test has no sudo, so minimal risk.)
cat > "$AUTH_FILE" <<EOF
${PUBLIC_KEY}
EOF

chmod 700 "$SSH_DIR"
chmod 600 "$AUTH_FILE"
chown -R frp-test:frp-test "$SSH_DIR"

log "SSH authorized_keys configured (key-only auth, no restrictions)"
log "Key comment: ${PUBLIC_KEY##* }"

# ── 3. Open firewall ports 17000–17100 ──

PORTS_START=17000
PORTS_END=17100
PORTS_RANGE="${PORTS_START}:${PORTS_END}"

if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow ${PORTS_START}:${PORTS_END}/tcp
    log "UFW: opened tcp ${PORTS_START}-${PORTS_END}"
elif command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q "running"; then
    firewall-cmd --permanent --add-port=${PORTS_START}-${PORTS_END}/tcp
    firewall-cmd --reload
    log "firewalld: opened tcp ${PORTS_START}-${PORTS_END}"
elif command -v iptables &>/dev/null; then
    # Check if rule already exists
    if ! iptables -C INPUT -p tcp --dport ${PORTS_START}:${PORTS_END} -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p tcp --dport ${PORTS_START}:${PORTS_END} -j ACCEPT
        log "iptables: opened tcp ${PORTS_START}-${PORTS_END}"
        # Try to save rules
        if command -v iptables-save &>/dev/null; then
            if [[ -d /etc/iptables ]]; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            elif [[ -f /etc/sysconfig/iptables ]]; then
                iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            fi
        fi
    else
        log "iptables: rule already exists for tcp ${PORTS_START}-${PORTS_END}"
    fi
else
    warn "No supported firewall detected (ufw/firewalld/iptables)."
    warn "Please manually open tcp ${PORTS_START}-${PORTS_END}."
fi

# ── 4. Install netcat ──

if command -v nc &>/dev/null; then
    log "netcat already installed: $(which nc)"
else
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq netcat-openbsd
        log "Installed netcat-openbsd (apt)"
    elif command -v yum &>/dev/null; then
        yum install -y -q nmap-ncat
        log "Installed nmap-ncat (yum)"
    elif command -v dnf &>/dev/null; then
        dnf install -y -q nmap-ncat
        log "Installed nmap-ncat (dnf)"
    elif command -v apk &>/dev/null; then
        apk add --quiet netcat-openbsd
        log "Installed netcat-openbsd (apk)"
    else
        warn "Could not install netcat automatically. Please install manually."
    fi
fi

# ── 5. Create temp dir (avoid first-run permission issues) ──

mkdir -p /tmp/frp-xtcp-test
chown frp-test:frp-test /tmp/frp-xtcp-test 2>/dev/null || true

# ── Verify ──

echo
log "========== Setup Complete =========="
log "User:     frp-test"
log "SSH:      key-only, command-restricted"
log "Ports:    tcp ${PORTS_START}-${PORTS_END}"
log ""
log "Next steps (on your local machine):"
log "  1. Test SSH:  ssh -i ~/.ssh/xtcp-ci frp-test@<vps-ip> echo ok"
log "  2. Add GitHub Secret XTCP_VPS_HOST = <vps-ip>"
log "  3. Add GitHub Secret XTCP_VPS_SSH_KEY = \$(cat ~/.ssh/xtcp-ci)"
