# XTCP Testing: Full Coverage Design

**Date:** 2026-06-28
**Status:** Approved
**Implementation:** Phase 1 → Phase 2

## Problem

XTCP NAT hole punch testing has two coverage gaps:

1. **Client-side code paths untested:** `frp-client/src/visitor.rs` and `frp-client/src/service.rs` XTCP provider/visitor flows have zero test coverage. Only server-side message routing is tested (via `xtcp_hole_punch.rs`).

2. **E2E compat tests guarded:** `compat-test.sh` XTCP tests (`test_g2r_xtcp`, `test_r2g_xtcp`) are behind `RUN_XTCP=1` because they require public internet for STUN probes and TCP simultaneous open.

## Solution Overview

Two-phase approach:

- **Phase 1 (VPS CI):** End-to-end XTCP tests with real NAT traversal. VPS hosts frps (public IP); two frpc instances run on GitHub Actions runner (behind NAT). Covers core happy path, encryption variants, and cross-implementation compat.

- **Phase 2 (Local):** Rust integration tests on localhost exercising fallback, error paths, retry logic, concurrency, and resource cleanup. No VPS required.

## Phase 1: VPS CI — End-to-End XTCP

### Architecture

```
GitHub Actions (ubuntu-latest)              VPS (public IP, frp-test user)
─────────────────────────────────────       ──────────────────────────────
compat-test.sh --frps-remote $IP:$PORT      frps (Rust or Go)
  ├─ Go frpc provider    ────TCP───→        bind 0.0.0.0:$PORT
  ├─ Go frpc visitor     ────TCP───→        no root needed (high port)
  ├─ Rust frpc provider  ────TCP───→
  ├─ Rust frpc visitor   ────TCP───→
  └─ echo server (local)
```

- Each frpc does its own STUN (reaches public STUN servers from GitHub Actions)
- TCP simultaneous open between two frpc processes behind same NAT (NAT hairpin)
- Tests real XTCP coordination through a frps with a public IP

### VPS Setup

- Dedicated user `frp-test`, no sudo, no shell access beyond frps management
- SSH key with `command=` restriction in `authorized_keys` to limit to frps lifecycle commands
- frps binds high port (17000+), no root required
- Firewall: open port range 17000–17100 for frps

### New Files

#### `scripts/remote-frps.sh`

Lifecycle management for frps on remote VPS.

```
Usage:
  bash scripts/remote-frps.sh start  <impl> <host> <port> <token> <ssh-key>
  bash scripts/remote-frps.sh stop   <host> <ssh-key>
  bash scripts/remote-frps.sh status <host> <ssh-key>

Commands:
  start  — scp frps binary → write config → nohup launch → wait until port ready
  stop   — kill frps process + cleanup temp files
  status — check if frps is running on remote host
```

`<impl>` is `rust` or `go`. `start` reads the binary from `target/release/frps` (Rust) or `/tmp/frp_<ver>_<os>_<arch>/frps` (Go).

#### `.github/workflows/xtcp-compat.yml`

```yaml
name: XTCP Compat
on:
  workflow_dispatch:
  schedule:
    - cron: '17 3 * * *'  # daily, off-peak

jobs:
  xtcp:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    if: ${{ secrets.XTCP_VPS_HOST != '' }}
    # Clean skip if secrets not configured — no CI failure.
    steps:
      - checkout
      - setup Rust (stable)
      - setup Go (>=1.22)
      - Build Rust frps/frpc (release)
      - Download Go frp (pre-built v0.69.1)
      - Run: bash scripts/compat-test.sh --frps-remote $VPS_HOST --xtcp-only

env:
  XTCP_VPS_HOST: ${{ secrets.XTCP_VPS_HOST }}
  XTCP_VPS_SSH_KEY: ${{ secrets.XTCP_VPS_SSH_KEY }}
  XTCP_VPS_USER: frp-test
```

GitHub Secrets required:
- `XTCP_VPS_HOST` — VPS public IP or hostname
- `XTCP_VPS_SSH_KEY` — private key for frp-test user

### Changes to `compat-test.sh`

1. **`--frps-remote <host>` flag:** When set, skip local frps startup. Write config with `bind_addr = "0.0.0.0"` (instead of `127.0.0.1`). Point frpc configs to remote host.

2. **`--xtcp-only` flag:** Run only XTCP-related tests (skip TCP/UDP/HTTP/STCP/KCP/V2 tests). Saves CI time.

3. **XTCP guard override:** When `--frps-remote` is set, automatically enable `RUN_XTCP=1`.

### Test Matrix (6 tests)

| Test | frps | Provider | Visitor | Encryption | Coverage |
|------|------|----------|---------|:----------:|----------|
| `xtcp-g2r-basic` | Rust | Go | Go | — | Go→Rust happy path |
| `xtcp-r2g-basic` | Go | Rust | Rust | — | Rust→Go happy path |
| `xtcp-g2r-enc` | Rust | Go | Go | ✅ enc+comp | Go→Rust encrypted bridge |
| `xtcp-r2g-enc` | Go | Rust | Rust | ✅ enc+comp | Rust→Go encrypted bridge |
| `xtcp-mixed-go-visitor` | Rust | Rust | Go | — | Go visitor ↔ Rust provider |
| `xtcp-mixed-rust-visitor` | Go | Go | Rust | — | Rust visitor ↔ Go provider |

Each test:
- Starts echo server on GitHub Actions runner
- Provider registers XTCP proxy, establishes work conn pool
- Visitor connects, does precheck + STUN + full NatHoleVisitor
- TCP simultaneous open between provider and visitor
- Echo data round-trip verification
- Data integrity assertion (payload matches)

## Phase 2: Local Integration Tests

All tests run on localhost CI (no VPS needed). Using existing `start_test_server` + `raw_login` infrastructure.

### New File: `frp-server/tests/xtcp_fallback.rs`

#### `xtcp_fallback_stcp_relay`
- Provider registers XTCP proxy, establishes work conn
- Visitor sends precheck (OK) + full NatHoleVisitor
- Provider sends NatHoleClient with **unreachable** candidate addresses (`10.255.255.1:1`)
- Server's NAT classifier tags both as EasyNAT → mode 0
- Server sends NatHoleResp to visitor with provider's addresses
- Visitor iterates candidates → TCP simultaneous open fails for each
- Visitor falls back: dials server → NewVisitorConn → bridges through STCP relay
- **Verify:** echo data round-trips correctly through STCP fallback path

#### `xtcp_fallback_all_candidates_fail`
- Provider sends 3 unreachable candidate addresses
- **Verify:** visitor tries all 3 in order, logs failure for each, then falls back

#### `xtcp_precheck_error`
- Visitor sends precheck for proxy name that doesn't exist
- Server returns `NatHoleResp { error: Some("...") }`
- **Verify:** visitor returns without entering phase 2

#### `xtcp_precheck_unexpected_response`
- Visitor sends precheck to a connection that the server drops immediately
- **Verify:** visitor handles the unexpected close gracefully (returns, does not panic)

#### `xtcp_stun_failure`
- Visitor configured with STUN server `127.0.0.1:1` (nothing listening)
- STUN discovery fails → `mapped_addrs` is empty
- Visitor still sends full NatHoleVisitor (mapped_addrs=None)
- **Verify:** flow continues past STUN failure gracefully

#### `xtcp_retry_loop`
- Provider sends unreachable candidates each time
- Visitor configured with `keep_tunnel_open=true, max_retries_an_hour=3`
- **Verify:** visitor makes exactly 4 attempts (initial + 3 retries), then falls back to STCP

#### `xtcp_nat_hole_timeout`
- Visitor sends precheck + full NatHoleVisitor
- Provider **never** sends NatHoleClient (simulates unresponsive provider)
- **Verify:** server's NAT hole session expires after `NAT_HOLE_TIMEOUT=10s`
- **Verify:** `sk_index` entry is cleaned up

### New File: `frp-server/tests/xtcp_edge.rs`

#### `xtcp_concurrent_sessions`
- Start 5 pairs of (provider + visitor) concurrently
- **Verify:** all 5 complete with correct data transfer
- **Verify:** no cross-session message routing (each session gets its own sid)

#### `xtcp_session_cleanup_after_report`
- Run normal XTCP flow with reachable addresses
- Provider sends NatHoleReport after hole punch
- **Verify:** server's `sk_index` no longer contains the proxy's secret key
- **Verify:** proxy port is released back to pool

#### `xtcp_encrypted_bridge`
- XTCP with `use_encryption=true` on provider
- Visitor also uses `use_encryption=true`
- **Verify:** encrypted bridge carries correct echo data

#### `xtcp_encrypted_compressed`
- XTCP with `use_encryption=true` AND `use_compression=true`
- **Verify:** compressed+encrypted bridge data is correct

### Addition to `xtcp_hole_punch.rs`

#### `xtcp_invalid_transaction_id`
- Provider sends `NatHoleClient` with `transaction_id` that doesn't match any active session
- **Verify:** server ignores or responds with error (does not panic/crash)

## Coverage Matrix

| Layer | Unit (always) | Phase 1 (VPS) | Phase 2 (local) |
|-------|:---:|:---:|:---:|
| Server message routing | ✅ existing | — | — |
| NAT classification | ✅ existing | — | — |
| NAT analysis / mode tables | ✅ existing | — | — |
| **frpc provider XTCP flow** | ❌ | ✅ | — |
| **frpc visitor XTCP flow** | ❌ | ✅ | — |
| **E2E data transfer (happy)** | ❌ | ✅ | — |
| **Multi-address negotiation** | ❌ | ✅ | — |
| **XTCP + encryption** | ❌ | ✅ | ✅ |
| **XTCP + compression** | ❌ | — | ✅ |
| **XTCP + enc + comp** | ❌ | — | ✅ |
| **STCP fallback** | ❌ | — | ✅ |
| **Precheck errors** | ❌ | — | ✅ |
| **STUN failure** | ❌ | — | ✅ |
| **Retry loop** | ❌ | — | ✅ |
| **NAT_HOLE_TIMEOUT** | ❌ | — | ✅ |
| **Concurrent sessions** | ❌ | — | ✅ |
| **Session cleanup** | ❌ | — | ✅ |
| **Invalid transaction_id** | ❌ | — | ✅ |

## Implementation Order

1. **Phase 2 first** (no external dependency): Write local integration tests. Catch bugs immediately.
2. **Phase 1 second** (requires VPS setup): Set up VPS user + CI workflow. Run manually first, then enable schedule.

## VPS Security Constraints

- User: `frp-test`, no sudo, no shell
- SSH `authorized_keys` restricted with `command=` to `remote-frps.sh` subcommands
- frps binds high ports only (17000+)
- Token generated per-test-run (random, invalid after CI job ends)
- No persistent state on VPS between test runs
