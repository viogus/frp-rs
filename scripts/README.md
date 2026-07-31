# XTCP Test Scripts

XTCP (NAT hole punch) end-to-end compatibility testing between Rust and Go frp implementations.

## Overview

```
┌─────────────────────────────────────────────────────┐
│ GitHub Actions (ubuntu-latest)        VPS (public IP)│
│ ─────────────────────────────       ──────────────── │
│ compat-test.sh --frps-remote $IP    frps (Rust/Go)   │
│   ├─ frpc provider ────TCP──────→   bind 0.0.0.0     │
│   ├─ frpc visitor  ────TCP──────→                     │
│   └─ echo server (localhost)                          │
└─────────────────────────────────────────────────────┘
```

Each frpc does its own STUN (reaches public STUN servers). TCP simultaneous open between provider and visitor behind same NAT (NAT hairpin). Real XTCP coordination through frps with public IP.

## Quick Start

### Local integration tests (no VPS needed)

```bash
# All 10 server-side XTCP protocol tests
cargo test -p frp-server xtcp

# Individual test files
cargo test -p frp-server --test xtcp_hole_punch
cargo test -p frp-server --test xtcp_fallback
cargo test -p frp-server --test xtcp_edge
```

### Local XTCP compat test (frps + both frpc on localhost)

```bash
# Build Rust binaries first
cargo build --release --bin frps --bin frpc
bash scripts/download-go-frp.sh 0.70.1

# Run only XTCP tests
RUN_XTCP=1 bash scripts/compat-test.sh --xtcp-only --verbose

# Run single test
RUN_XTCP=1 bash scripts/compat-test.sh --test xtcp-r2r-basic --verbose
```

### Remote VPS XTCP compat test

```bash
# Build + download as above, then:
bash scripts/compat-test.sh \
    --frps-remote <VPS_IP> \
    --xtcp-only \
    --verbose
```

Requires `XTCP_VPS_SSH_KEY` env var set to the SSH private key path.

## Scripts

### `compat-test.sh` — XTCP Flags

| Flag | Description |
|------|-------------|
| `--frps-remote <host>` | Use VPS-hosted frps instead of local. Sets `RUN_XTCP=1` automatically. |
| `--xtcp-only` | Skip all non-XTCP tests (TCP, UDP, MUX, HTTP, STCP, KCP, QUIC, V2). |
| `--xtcp-only --frps-remote <host>` | CI mode: remote frps, XTCP tests only. |

Env vars used when `--frps-remote` is set:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `XTCP_VPS_SSH_KEY` | Yes | — | Path to SSH private key for `frp-test` user |
| `XTCP_VPS_USER` | No | `frp-test` | SSH username on VPS |
| `GO_FRP_VERSION` | No | `0.70.1` | Go frp version for test |

### `remote-frps.sh` — VPS frps Lifecycle

```
Usage:
  bash scripts/remote-frps.sh start  <impl> <host> <port> <token> <ssh-key>
  bash scripts/remote-frps.sh stop   <host> <ssh-key>
  bash scripts/remote-frps.sh status <host> <ssh-key>

<impl>: "rust" or "go"
```

**`start`** — Uploads frps binary + config to VPS, starts via nohup, waits for port readiness. **Prints the actual port used as the last line of stdout** (for port conflict fallback capture).

**`stop`** — Kills the frps process, cleans up `/tmp/frp-xtcp-test` on the VPS.

**`status`** — Reports `running`, `stopped`, or `unknown (ssh failed)`.

## Port Conflict Avoidance

VPS may have other programs using ports. `remote-frps.sh start` handles this:

1. Checks requested port availability on VPS via `ss -tlnp`
2. If busy, scans `port .. port+100` for first available port
3. Uses first free port
4. Echoes actual port as last stdout line → `compat-test.sh` captures via `$(... | tail -1)`
5. Exits with error if no port available in range

No TOCTOU fix needed — acceptable race for CI. VPS frps lifetime is per-test (~5 seconds).

## Test Matrix: 16 Pairwise Tests

### Unencrypted (2³ = 8 combinations)

| # | frps | Provider | Visitor | Test name |
|---|------|----------|---------|------------|
| 1 | Go | Go | Go | `xtcp-g2g-basic` |
| 2 | Go | Go | Rust | `xtcp-go-frps-go-prov-rust-vis` |
| 3 | Go | Rust | Go | `xtcp-go-frps-rust-prov-go-vis` |
| 4 | Go | Rust | Rust | `xtcp-r2g-basic` |
| 5 | Rust | Go | Go | `xtcp-g2r-basic` |
| 6 | Rust | Go | Rust | `xtcp-rust-frps-go-prov-rust-vis` |
| 7 | Rust | Rust | Go | `xtcp-rust-frps-rust-prov-go-vis` |
| 8 | Rust | Rust | Rust | `xtcp-r2r-basic` |

### Encrypted (+ compression) — same 8 combos

| # | frps | Provider | Visitor | Test name |
|---|------|----------|---------|------------|
| 9 | Go | Go | Go | `xtcp-g2g-enc` |
| 10 | Go | Go | Rust | `xtcp-go-frps-go-prov-rust-vis-enc` |
| 11 | Go | Rust | Go | `xtcp-go-frps-rust-prov-go-vis-enc` |
| 12 | Go | Rust | Rust | `xtcp-r2g-enc` |
| 13 | Rust | Go | Go | `xtcp-g2r-enc` |
| 14 | Rust | Go | Rust | `xtcp-rust-frps-go-prov-rust-vis-enc` |
| 15 | Rust | Rust | Go | `xtcp-rust-frps-rust-prov-go-vis-enc` |
| 16 | Rust | Rust | Rust | `xtcp-r2r-enc` |

**Execution order:** Baselines first (`g2g-basic` → `r2r-basic`). If baseline fails, all tests using that frps are suspect. Then cross-tests. Encrypted variants last.

## VPS Setup (Manual Prerequisites)

Phase 1 CI requires a VPS with public IP. **Run `scripts/vps-setup.sh` as root on the VPS** to automate steps 1–4 below.

```bash
# On your local machine: generate a dedicated key pair
ssh-keygen -t ed25519 -f ~/.ssh/xtcp-ci -C "xtcp-ci" -N ""

# Copy vps-setup.sh to VPS and run as root
scp scripts/vps-setup.sh root@<VPS_IP>:/tmp/
ssh root@<VPS_IP> "bash /tmp/vps-setup.sh '$(cat ~/.ssh/xtcp-ci.pub)'"
```

Then add GitHub Secrets (step 5 below).

### Manual steps (if not using vps-setup.sh)

```bash
# On VPS (as root)
useradd -m -s /bin/bash frp-test
passwd -l frp-test  # lock password, SSH key only
```

User has no sudo. No shell restrictions needed — `remote-frps.sh` uses SSH command forwarding.

### 2. Configure SSH key

```bash
# On your machine: generate dedicated key pair
ssh-keygen -t ed25519 -f ~/.ssh/xtcp-ci -C "xtcp-ci" -N ""

# Copy public key to VPS
ssh-copy-id -i ~/.ssh/xtcp-ci.pub frp-test@<VPS_IP>
```

### 3. Restrict authorized_keys (optional, recommended)

On VPS, edit `~frp-test/.ssh/authorized_keys`. Add restrictions before the key:

```
restrict,command="/bin/bash -c 'cd /tmp/frp-xtcp-test && exec bash'" ssh-ed25519 AAAA...
```

This limits the key to running commands only within the temp directory.

### 4. Open firewall ports

```bash
# UFW
ufw allow 17000:17100/tcp

# iptables
iptables -A INPUT -p tcp --dport 17000:17100 -j ACCEPT
```

frps binds high ports only (17000+). Port range must cover `start_port .. start_port+100` for conflict fallback. Recommend opening 17000–17100.

### 5. Install nc (netcat) on VPS

```bash
apt install netcat-openbsd  # or: yum install nmap-ncat
```

`remote-frps.sh` uses `nc -z` to verify frps is ready.

### 6. Add GitHub Secrets

| Secret | Value |
|--------|-------|
| `XTCP_VPS_HOST` | VPS public IP or hostname |
| `XTCP_VPS_SSH_KEY` | Content of `~/.ssh/xtcp-ci` (private key) |

### 7. Verify manually

```bash
# Test SSH connectivity
XTCP_VPS_USER=frp-test bash scripts/remote-frps.sh status <VPS_IP> ~/.ssh/xtcp-ci
# Expected: "stopped"

# Test full flow
cargo build --release --bin frps --bin frpc
bash scripts/download-go-frp.sh 0.70.1
XTCP_VPS_SSH_KEY=~/.ssh/xtcp-ci bash scripts/compat-test.sh \
    --frps-remote <VPS_IP> --xtcp-only --verbose
```

## CI Workflow

`.github/workflows/xtcp-compat.yml`:

- **Triggers:** `workflow_dispatch` (manual) + daily cron `17 3 * * *` (UTC)
- **Timeout:** 25 minutes
- **Skip:** Clean skip if `XTCP_VPS_HOST` secret is not configured
- **Cache:** Cargo + Go frp binary cached between runs

## Architecture Notes

### XTCP NAT Hole Punch Flow

```
Visitor                Server                 Provider
  │                      │                       │
  │── NatHoleVisitor ──→ │ (precheck)            │
  │←─ NatHoleResp(OK) ── │                       │
  │                      │                       │
  │── NatHoleVisitor ──→ │ (full, STUN addrs)    │
  │                      │── StartWorkConn ────→ │ (on work conn)
  │                      │── NatHoleSid ───────→ │ (on work conn)
  │                      │                       │
  │                      │←─ NatHoleClient ───── │ (on control, STUN addrs)
  │                      │   NAT analysis        │
  │←─ NatHoleResp ────── │ (provider candidates) │
  │                      │── NatHoleResp ──────→ │ (visitor candidates)
  │                      │                       │
  │── TCP simultaneous open ──────────────────→ │
  │←══════════ P2P bridge ════════════════════→ │
  │                      │                       │
  │                      │←─ NatHoleReport ──── │ (session cleanup)
```

### STCP Fallback

If hole punch fails (all candidates unreachable), visitor falls back to STCP relay:

1. Visitor dials server
2. Sends `NewVisitorConn` with `sk` (secret key)
3. Server routes to correct proxy via `sk_index`
4. Data bridged through server (no P2P)

### Encryption Flag Propagation

```
NewProxy.use_encryption (Option<bool>)
  → ProxyInfo.use_encryption (bool, unwrap_or(false))
    → ProxyManager lookup
      → StartWorkConn.use_encryption (Option<bool>, Some(true) or None)
        → frpc reads flag, sets up encrypted bridge
```

`None` → omitted from JSON (backward compatible with Go frp `omitempty`).

## Rust Integration Tests (Phase 2)

Localhost tests in `frp-server/tests/`. No VPS required. Always run in CI.

| File | Tests | What it covers |
|------|-------|----------------|
| `xtcp_hole_punch.rs` | 2 | Message routing + invalid sid (server-side protocol) |
| `xtcp_fallback.rs` | 5 | Precheck errors, disconnect safety, invalid sid, report cleanup |
| `xtcp_edge.rs` | 3 | Concurrent sessions, multi-provider isolation, encryption flags |

All 10 tests use raw V1 TCP protocol messages against in-process frps — no actual NAT traversal.

## Files

| File | Purpose |
|------|---------|
| `scripts/compat-test.sh` | Main compat test harness (~3870 lines) |
| `scripts/remote-frps.sh` | VPS frps lifecycle (start/stop/status) |
| `scripts/download-go-frp.sh` | Download Go frp pre-built binaries |
| `.github/workflows/xtcp-compat.yml` | Daily CI workflow for XTCP |
| `frp-server/tests/xtcp_hole_punch.rs` | Server message routing tests |
| `frp-server/tests/xtcp_fallback.rs` | Error/timeout server tests |
| `frp-server/tests/xtcp_edge.rs` | Concurrency/encryption server tests |
| `docs/superpowers/specs/2026-06-28-xtcp-testing-design.md` | Design spec |
| `docs/superpowers/plans/2026-06-28-xtcp-testing.md` | Implementation plan |

## Troubleshooting

**`remote frps did not start`**: Check SSH connectivity, binary exists on local machine, VPS has no firewall blocking the port.

**`visitor port not reachable`**: XTCP hole punch failed. Check provider/visitor logs in `$TEST_DIR/<name>/`. STUN servers must be reachable from the runner.

**Port conflict**: Handled automatically — `remote-frps.sh` scans for available port. If all 101 ports busy, something else is wrong on the VPS.

**CI skips workflow**: Add `XTCP_VPS_HOST` secret — workflow clean-skips without it.
