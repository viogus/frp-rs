# Bridge Flush Latency Audit

**Date:** 2026-07-12
**Scope:** L3 latency audit — confirm bridge flush behavior introduces no interactive-data stall
**Files audited:**
- `frp-core/src/bridge.rs` — `bridge_encrypted`, `bridge_plain`
- `frp-server/src/control/bridge.rs` — `assign_work_to_proxy` fast-path dispatch
**Verdict:** CLEAN — no code change required.

---

## 1. `bridge_encrypted` — flush after every write (latency-appropriate)

### user_to_work direction
| Site | Line | Trigger |
|------|------|---------|
| `enc_work_w.flush()` | 151 | Every write to encrypted work connection |

After `write_all(&processed)` on line 150, `flush()` on line 151 forces the encrypted chunk to wire immediately. For streaming CFB + optional Snappy compression this is the right call — there is no "batch" optimization to apply because the encrypted framing is inherently per-chunk (4-byte BE length prefix + 16-byte IV). Interactive data is never held awaiting a larger chunk.

### work_to_user direction
| Site | Line | Trigger |
|------|------|---------|
| `user_w.flush()` | 191 | Every non-empty write to user connection |

Decrypted plaintext is written to `user_w` and flushed on line 191. Same per-chunk behavior.

### IV eager flush
| Site | Line | Trigger |
|------|------|---------|
| `enc_work_w.flush()` | 113 | First poll_flush, before any data |

CipherWriter sends its random IV immediately on first `poll_flush` (line 113). This unblocks the peer's CipherReader, preventing a deadlock that previously existed in dual-CipherWriter setups. The eager IV is _good_ for latency — the peer does not wait for user data to arrive before it can begin decrypting.

### Loop exit
| Site | Line | Trigger |
|------|------|---------|
| `enc_work_w.shutdown()` | 157 | Loop exit (only when no pre_read) |
| decompressor flush → `user_w.write_all()` → `user_w.flush()` | 195–206 | Loop exit |
| `user_w.shutdown()` | 216 | Loop exit |

Both directions flush remaining buffered data (including decompressor residual) before signalling EOF. No data is orphaned.

---

## 2. `bridge_plain` — batched-flush with short-read escalation (correct)

`bridge_plain` uses the throughput project's batched-flush logic:

### user_to_work direction
| Site | Line | Trigger |
|------|------|---------|
| `work_w.flush()` | 278 | `use_compression || n < cap` |
| `work_w.flush()` | 287 | Loop exit (unconditional, unconditional in practice) |

### work_to_user direction
| Site | Line | Trigger |
|------|------|---------|
| `user_w.flush()` | 328 | `use_compression || n < cap` |
| `user_w.flush()` | 335 | Loop exit (unconditional) |
| decompressor flush → `user_w.write_all()` → `user_w.flush()` | 337–355 | Loop exit |

### Flush decision rule (lines 278, 328)

```
if (use_compression || n < cap) { flush() }
```

- **`n < cap`** (short/interactive read) → flush immediately. Interactive protocol messages (SSH, HTTP headers, database query results) are typically much smaller than `BUFFER_SIZE`, so they get pushed to wire at once.
- **`n == cap`** (full buffer) → defer flush. A full-capacity read means more data is likely queued behind it. Batching avoids a syscall per chunk without hurting interactive latency (since interactive traffic rarely fills a buffer).
- **`use_compression`** → always flush. Snappy-compressed chunks are sent as soon as available because compression changes the framing (the downstream needs to reassemble).

### Loop-exit flush (lines 287, 335)

Both directions unconditionally flush before shutdown. The decompressor residual flush (lines 337–355) catches any buffered compressed data that hasn't yet been written to `user_w`.

### Unit test coverage

Test `bridge_plain_batches_flushes_on_full_reads` (lines 506–551) validates the batching: a reader that yields two full-capacity chunks results in exactly **1** flush (the loop-exit flush), not 2 per-chunk flushes. This verifies the condition `n < cap` gates the flush decision correctly.

---

## 3. `frp-server/src/control/bridge.rs` — fast path (copy_bidirectional) latency

`assign_work_to_proxy` (line 251) has three code paths:

### (a) XTCP STCP fallback (lines 441–451)

```rust
tokio::io::copy_bidirectional(&mut user_conn, &mut work_conn).await
```

`copy_bidirectional` flushes the write side when the read side returns `Poll::Pending` — i.e., when there is no more data to read right now. For interactive traffic this means a short exchange is immediately forwarded; the function does not wait for a full buffer. This path handles the XTCP STCP fallback case where bridge_plain's `join!`-pattern premature-FIN was causing ECONNRESET.

### (b) Plain fast path (lines 452–469)

```rust
tokio::io::copy_bidirectional(&mut user_conn, &mut work_conn).await
```

Same `copy_bidirectional` call. Gated on `!comp_key && bridge_pre_read.is_empty() && req.response_headers.is_empty()`. Used for normal TCP/STCP proxies with no encryption, compression, VHost pre-read, or response header injection. Latency-appropriate for the same reason as (a).

### (c) Slow path (lines 470–479)

Calls `bridge_plain` (for compression, pre_read, or header injection) or `bridge_plain` with `ResponseHeaderInjector`. Falls through to the batched-flush logic confirmed in Section 2.

### No data-stall path

All three paths flush as soon as data is available:
- `copy_bidirectional` flushes when reads go pending (interactive-friendly)
- `bridge_plain` flushes on short reads (interactive-friendly) and defers only on full-capacity reads (throughput-friendly, harmless for latency)
- `bridge_encrypted` flushes every chunk

No path holds interactive data waiting for a full buffer.

---

## Summary

| File | Flush site | Trigger | Verdict |
|------|-----------|---------|---------|
| `frp-core/src/bridge.rs:151` | `enc_work_w.flush()` | After every encrypted write | **Clean** — per-chunk flush matches streaming CFB |
| `frp-core/src/bridge.rs:191` | `user_w.flush()` | After every decrypted write | **Clean** — per-chunk flush |
| `frp-core/src/bridge.rs:278` | `work_w.flush()` | `use_compression \|\| n < cap` | **Clean** — short-read escalation, full-read deferral |
| `frp-core/src/bridge.rs:287` | `work_w.flush()` | Loop exit | **Clean** — no data orphaned |
| `frp-core/src/bridge.rs:328` | `user_w.flush()` | `use_compression \|\| n < cap` | **Clean** — short-read escalation, full-read deferral |
| `frp-core/src/bridge.rs:335` | `user_w.flush()` | Loop exit | **Clean** — no data orphaned |
| `frp-core/src/bridge.rs:195–206` | decompressor flush → write → flush | Loop exit | **Clean** — decompressor residual handled |
| `frp-core/src/bridge.rs:337–355` | decompressor flush → write → flush | Loop exit | **Clean** — decompressor residual handled |
| `frp-server/src/control/bridge.rs:443,461` | `copy_bidirectional` | Read pending | **Clean** — flushes when read side idle |
| `frp-server/src/control/bridge.rs:476,478` | `bridge_plain` (via slow path) | Delegates to above | **Clean** — covered by batched-flush logic |

**Result:** No interactive-data stall found. Current flush behavior is latency-appropriate across all three bridge paths. **Zero code change.**
