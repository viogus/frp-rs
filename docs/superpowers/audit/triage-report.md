# Go frp dev HEAD Full Audit — Triage Report

**Date:** 2026-07-21
**Go commit:** d486018
**Total findings:** 61 (7 CRITICAL, 22 MEDIUM, 29 LOW, 3 COSMETIC)

## CRITICAL Findings (7)

Must fix — these break Go↔Rust interop.

| # | Subsystem | Title | Fix Group |
|---|-----------|-------|-----------|
| C1 | Auth | Token timestamp freshness check breaks interop | **Config** |
| C2 | Server | Control replacement lifecycle lacks generation-aware serialization | **Server** |
| C3 | Server | ClientRegistry with control generation awareness missing | **Server** |
| C4 | Server | Two-phase login (Add-Activate-completeLogin) not implemented | **Server** |
| C5 | XTCP | PublicNetwork detection broken — empty local_ips | **XTCP/NAT** |
| C6 | XTCP | STUN CHANGED_ADDRESS/OTHER_ADDR attribute missing | **XTCP/NAT** |
| C7 | XTCP | Visitor assisted_addrs sends wrong data | **XTCP/NAT** |

## MEDIUM Findings (22)

Should fix — behavioral divergences that degrade interop.

Key ones to prioritize:
- M1: heartbeat_interval unconditional (config fix)
- M2: nat_hole_stun_server default empty (config fix)
- M3: tcp_mux default depends on feature flag (config fix)
- M4: proxy_bind_addr fallback missing (config fix)
- M5: Missing heartbeat timeout detection (client fix)
- M6: Missing proxy phase state machine (client fix)
- M7: KCP XOR comment misleading (doc fix)
- M8: Group health check TODO wrong (doc fix)
- M9: Missing config store CRUD (feature gap)
- M10: TCP group per-proxy ports (server fix)
- M11: HTTP group health check awareness (server fix)
- M12: Bandwidth limit mode semantics (server fix)
- M13: AlwaysAuthPass missing (server fix)
- M14: ServerAdditionalAuthScopes differs (server fix)
- M15-M22: Various (see individual finding files)

## Fix Strategy

1. Fix CRITICAL first (3 fix groups in sequence)
2. Fix MEDIUM next (batched by subsystem)
3. Fix LOW/COSMETIC as time permits
4. Add compat tests for every CRITICAL and MEDIUM fix
5. Full verification pass
