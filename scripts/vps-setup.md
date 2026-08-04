# VPS Setup for XTCP CI

One-shot VPS configuration. Run `vps-setup.sh` as root on the VPS.

## Prerequisites

- VPS with public IP, root access
- Local machine with `ssh-keygen`

## Usage

### 1. Generate key pair (local)

```bash
ssh-keygen -t ed25519 -f ~/.ssh/xtcp-ci -C "xtcp-ci" -N ""
```

### 2. Run setup on VPS

```bash
scp scripts/vps-setup.sh root@<VPS_IP>:/tmp/
ssh root@<VPS_IP> "bash /tmp/vps-setup.sh '$(cat ~/.ssh/xtcp-ci.pub)'"
```

### 3. Add GitHub Secrets

| Secret | Value |
|--------|-------|
| `XTCP_VPS_HOST` | VPS public IP |
| `XTCP_VPS_SSH_KEY` | `cat ~/.ssh/xtcp-ci` |

### 4. Test

```bash
XTCP_VPS_SSH_KEY=~/.ssh/xtcp-ci bash scripts/compat-test.sh \
    --frps-remote <VPS_IP> --xtcp-only --verbose
```

## What the Script Does

| Step | Detail |
|------|--------|
| 1. Create user | `frp-test`, no sudo, password locked |
| 2. SSH config | `authorized_keys` with plain key, no options (`restrict`/`command=` not applied — see Security below) |
| 3. Firewall | Opens tcp 17000–17100 (auto-detect ufw / firewalld / iptables) |
| 4. netcat | Installs if missing (apt/yum/dnf/apk) |

## Security

- `frp-test` has no sudo, no password
- SSH key is written **without** options (plain key). `vps-setup.sh` deliberately
  skips `restrict`/`command=` — `restrict` causes SSH agent hangs on some
  OpenSSH versions. `command=` (limiting the key to `/tmp/frp-xtcp-test`) and
  `restrict` (disabling port forwarding, agent forwarding, pty, X11) remain
  available as **manual** hardening options — see "Restrict authorized_keys"
  in `scripts/README.md`.
- Token is ephemeral (generated per test run)
- No persistent state on VPS between test runs (`remote-frps.sh stop` cleans `/tmp/frp-xtcp-test`)
