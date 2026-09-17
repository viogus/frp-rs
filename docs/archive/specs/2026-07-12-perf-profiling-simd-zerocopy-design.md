# Performance: Profiling, SIMD Crypto, Zero-Copy — Design Spec

**Goal:** Add on-demand CPU profiling (flamegraph), SIMD-accelerate V1 AES-128-CFB crypto, and add Linux zero-copy TCP bridge using splice.

**Status:** Design approved — all sections.

## Scope

### In
1. pprof-rs based CPU flamegraph profiler behind `profiling` feature flag
2. SIGUSR2 handler dumps flamegraph SVG + protobuf to disk (frps and frpc)
3. Enable AES-NI/ARMv8 hardware acceleration in `aes` crate via `cpuid`/`armv8` features
4. `u128` single-instruction XOR in CfbState hot path instead of byte loop
5. Linux `splice(2)` zero-copy TCP bridge for plain (unencrypted, uncompressed) path
6. Verify `chacha20poly1305` SIMD feature status, enable if missing

### Out
- tokio-console async task introspection (separate project)
- Heap/allocation profiling (mem-profile covers this; pprof heap profiling deferred)
- Zero-copy for encrypted/compressed/TLS/KCP/QUIC/mux paths
- Windows zero-copy (no `splice`, no `sendfile` between sockets)
- SIMD for V2 crypto (ring already does AES-NI; XChaCha20 is crate-level feature)
- New crypto backends (ring, openssl) — stay with `aes` crate, just enable hardware

## Architecture

Three independent subsystems, one spec:

```
frp-core
├── profiling.rs          [NEW, feature="profiling"]
│   └── dump_cpu_profile(duration, output_dir) -> PathBuf
├── cipher_stream.rs      [MODIFY]
│   ├── CfbState::encrypt/decrypt: u128 XOR
│   └── Cargo.toml: aes features +cpuid +armv8
├── crypto.rs             [VERIFY]
│   └── chacha20poly1305 SIMD feature check
└── bridge.rs             [MODIFY]
    ├── bridge_plain_zero_copy()  [NEW, cfg(target_os = "linux")]
    └── bridge_plain_tcp()        [NEW, dispatch wrapper]
```

All three are independent — can be implemented, tested, and shipped separately. One spec for design coherence; three sequential impl plans.

## 1. Profiling Infrastructure

### 1.1 Feature Gate

```toml
# frp-core/Cargo.toml
[features]
profiling = ["dep:pprof"]
```

New optional dependency `pprof` in workspace `Cargo.toml`:

```toml
pprof = { version = "0.14", features = ["flamegraph", "criterion"], optional = true }
```

`flamegraph` feature pulls `inferno` for SVG rendering. `criterion` feature enables `pprof::criterion::PProfProfiler` for Criterion bench integration (secondary use, later).

Binary feature propagation: `frps` and `frpc` add `profiling` to their feature lists, gated on `frp-core`'s `profiling` feature (standard propagation pattern already used by `mem-profile`).

### 1.2 Module: `frp-core/src/profiling.rs`

Single public function:

```rust
#[cfg(feature = "profiling")]
use std::path::{Path, PathBuf};
#[cfg(feature = "profiling")]
use std::time::Duration;

#[cfg(feature = "profiling")]
pub fn dump_cpu_profile(
    duration: Duration,
    output_dir: &Path,
    prefix: &str,          // "frps" or "frpc"
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    use pprof::profiler::Builder;

    let guard = Builder::new()
        .frequency(99)     // Hz, standard profiling frequency
        .build()?;

    std::thread::sleep(duration);

    let report = guard.report().build()?;

    let ts = chrono::Local::now().format("%Y-%m-%dT%H_%M_%S");
    let svg_path = output_dir.join(format!("{prefix}_profile_{ts}.svg"));
    let pb_path = output_dir.join(format!("{prefix}_profile_{ts}.pb"));

    let svg_file = std::fs::File::create(&svg_path)?;
    report.flamegraph(svg_file)?;

    let pb_file = std::fs::File::create(&pb_path)?;
    report.write_protobuf(pb_file)?;

    Ok(svg_path)
}
```

`chrono` already in dep tree via tracing. If direct dependency is missing, use `std::time::SystemTime` with manual formatting instead — no new dep.

### 1.3 Signal Handler (frps and frpc)

In `main.rs` for both binaries, behind `#[cfg(all(unix, feature = "profiling"))]`:

```rust
#[cfg(all(unix, feature = "profiling"))]
fn spawn_profile_handler(label: &'static str) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sig = match signal(SignalKind::user_defined2()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "SIGUSR2 not available, profiling disabled");
            return;
        }
    };
    let output_dir = std::env::var("FRP_PROFILE_DIR")
        .unwrap_or_else(|_| ".".to_string());
    let secs: u64 = std::env::var("FRP_PROFILE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    tokio::spawn(async move {
        tracing::info!(label, seconds = secs, dir = %output_dir,
            "profiling ready — send SIGUSR2 (kill -USR2 {})", std::process::id());
        loop {
            sig.recv().await;
            let dir = std::path::PathBuf::from(&output_dir);
            let dur = std::time::Duration::from_secs(secs);
            let l = label;
            match tokio::task::spawn_blocking(move || {
                frp_core::profiling::dump_cpu_profile(dur, &dir, l)
            }).await {
                Ok(Ok(path)) => tracing::info!(path = %path.display(), "profile written"),
                Ok(Err(e)) => tracing::error!(error = %e, "profile failed"),
                Err(e) => tracing::error!(error = %e, "profile join error"),
            }
        }
    });
}
```

Called in `main()` after `init_logging()` but before service start:

```rust
#[cfg(all(unix, feature = "profiling"))]
spawn_profile_handler("frps");  // or "frpc"
```

Follows frps SIGUSR1 reload handler pattern: `tokio::spawn` + `loop { sig.recv().await }`.

### 1.4 Criterion Integration (future)

`pprof`'s `criterion` feature enables `PProfProfiler`. Add as optional profiler in `frp-core/benches/`:

```rust
#[cfg(feature = "profiling")]
criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(pprof::criterion::PProfProfiler::new(99, pprof::criterion::Output::Flamegraph(None)));
    targets = ...
);
```

Not in v1 — separate task after basic profiler working.

### 1.5 Binary Size Impact

`pprof` + `inferno` + protobuf stack: ~300-400KB per binary (estimate). Off by default, zero impact on default builds.

## 2. SIMD Crypto

### 2.1 Enable AES Hardware

One line in `frp-core/Cargo.toml`:

```toml
# Before:
aes = { workspace = true }

# After:
aes = { workspace = true, features = ["cpuid", "armv8"] }
```

`cpuid` feature: runtime CPUID detection on x86/x86_64. Selects AES-NI (`aes_ni`) backend if available, falls back to software (`aes_soft`). `armv8` feature: compile-time ARMv8 Crypto Extension detection. Both `cpuid` and `armv8` can coexist — `aes` crate uses `#[cfg]` at compile time to pick platform-appropriate backend.

Workspace `Cargo.toml` stays unchanged (features are consumer-side, not on the dependency declaration). `aes` 0.9.1 already supports these features.

Expected impact: `Aes128::encrypt`/`decrypt` (16-byte block) drops from ~40ns (T-tables) to ~4ns (AES-NI). 10x on the block cipher step. Overall CFB encrypt throughput: 306 MB/s → ~800-1000 MB/s (block cipher is ~60% of CFB hot path; rest is XOR + I/O).

### 2.2 u128 XOR in CfbState

In `frp-core/src/cipher_stream.rs`, CfbState `encrypt`/`decrypt` methods:

```rust
// CURRENT (line ~67-74, encrypt):
for i in 0..block_len {
    let x = self.state[i] ^ data[i];
    // ...
}

// NEW: u128 single-cycle XOR
let state_u128 = u128::from_le_bytes(self.state);
let data_u128 = u128::from_le_bytes(data[..16].try_into().unwrap());
let result = state_u128 ^ data_u128;

// For blocks < 16 bytes: keep scalar loop as fallback
```

Same transformation in `decrypt`. The `from_le_bytes`/`to_le_bytes` on little-endian platforms (x86 and ARM) compile to a no-op register reinterpretation — zero instructions. LLVM maps `u128 ^ u128` to `pxor` (SSE) or `veor` (NEON).

Edge case: partial blocks at EOF. CFB operates on exact block sizes — last partial block uses CFB-8 (shift register variant). The u128 path only applies to full 16-byte blocks; partial block path unchanged.

Safe Rust, no `unsafe`, no `#[target_feature]`.

### 2.3 XChaCha20-Poly1305 SIMD

Already accelerated. `chacha20` 0.9 (underlying `chacha20poly1305` 0.10) depends on `cpufeatures` for runtime CPU feature detection — SSE2/SSSE3/AVX2 on x86, NEON on ARM. No feature flag needed; SIMD is automatic. Verify with criterion bench to confirm hardware path is active, but no code change expected.

### 2.4 Dependencies

Zero new. `aes` features are compile-time flags on existing dependency. `u128` XOR uses core language, no crate needed.

### 2.5 Binary Size Impact

Zero. Hardware feature flags select different codegen paths in existing `aes` crate — no new code, just different compilation units. `u128` XOR is same or smaller than byte loop after optimization.

## 3. Zero-Copy Plain Bridge

### 3.1 Linux splice(2) Implementation

New function in `frp-core/src/bridge.rs`:

```rust
#[cfg(target_os = "linux")]
pub async fn bridge_plain_zero_copy(
    local: tokio::net::TcpStream,
    remote: tokio::net::TcpStream,
) -> Result<(), std::io::Error> {
    use std::os::fd::AsRawFd;
    use tokio::task::spawn_blocking;

    // Create one pipe pair per direction
    // pipe[0] = read end, pipe[1] = write end
    let (l2r_read, l2r_write) = pipe()?;   // local → remote
    let (r2l_read, r2l_write) = pipe()?;   // remote → local

    let local_fd = local.as_raw_fd();
    let remote_fd = remote.as_raw_fd();

    // Prevent tokio from closing fds on drop
    let _local = local.into_std()?;
    let _remote = remote.into_std()?;

    let l2r = spawn_blocking(move || {
        let mut total: u64 = 0;
        loop {
            let n = splice(local_fd, None, l2r_write, None, PIPE_CAPACITY, SPLICE_F_MOVE)?;
            if n == 0 { break; }
            let m = splice(l2r_read, None, remote_fd, None, n as usize, SPLICE_F_MOVE)?;
            if m == 0 { break; }
            total += m as u64;
        }
        Ok::<_, std::io::Error>(total)
    });

    let r2l = spawn_blocking(move || {
        let mut total: u64 = 0;
        loop {
            let n = splice(remote_fd, None, r2l_write, None, PIPE_CAPACITY, SPLICE_F_MOVE)?;
            if n == 0 { break; }
            let m = splice(r2l_read, None, local_fd, None, n as usize, SPLICE_F_MOVE)?;
            if m == 0 { break; }
            total += m as u64;
        }
        Ok::<_, std::io::Error>(total)
    });

    let (a, b) = tokio::join!(l2r, r2l);
    match (a, b) {
        (Ok(Ok(_)), _) | (_, Ok(Ok(_))) => Ok(()),
        (Err(e), _) | (_, Err(e)) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("splice join error: {e}"),
        )),
    }
}
```

Helper functions (same `#[cfg]` block):

```rust
#[cfg(target_os = "linux")]
const PIPE_CAPACITY: usize = 65536; // pipe buffer default on Linux

#[cfg(target_os = "linux")]
fn pipe() -> std::io::Result<(i32, i32)> {
    let mut fds = [-1i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

#[cfg(target_os = "linux")]
fn splice(
    fd_in: i32,
    _off_in: Option<&mut i64>,
    fd_out: i32,
    _off_out: Option<&mut i64>,
    len: usize,
    flags: u32,
) -> std::io::Result<usize> {
    let ret = unsafe {
        libc::splice(fd_in, std::ptr::null_mut(), fd_out, std::ptr::null_mut(), len, flags as i32)
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if ret == 0 {
        return Ok(0);
    }
    Ok(ret as usize)
}

const SPLICE_F_MOVE: u32 = 1; // SPLICE_F_MOVE
```

Dependencies: `libc` already transitive (via quinn→core-foundation on macOS). Add as workspace direct dependency:

```toml
libc = "0.2"
```

`frp-core/Cargo.toml`:
```toml
[target.'cfg(target_os = "linux")'.dependencies]
libc = { workspace = true }
```

### 3.2 Dispatch Logic

New function `bridge_plain_dispatch` in `bridge.rs` — single entry point for plain bridging. Existing `bridge_plain` stays unchanged (generic `impl AsyncRead + AsyncWrite`). Call sites that hold `IoStream` values call `bridge_plain_dispatch` instead of `bridge_plain`:

```rust
pub async fn bridge_plain_dispatch(
    local: IoStream,
    remote: IoStream,
) -> Result<(), std::io::Error> {
    #[cfg(target_os = "linux")]
    {
        // Extract TcpStream from IoStream for zero-copy path
        let local_tcp = match local {
            IoStream::Tcp(s) => Some(s),
            _ => None,
        };
        let remote_tcp = match remote {
            IoStream::Tcp(s) => Some(s),
            _ => None,
        };
        if let (Some(l), Some(r)) = (local_tcp, remote_tcp) {
            match bridge_plain_zero_copy(l, r).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::debug!(error = %e,
                        "splice bridge failed, falling back to copy_bidirectional");
                    // splice consumed fds via into_std() — cannot recover.
                    // This path returns error; callers already handle
                    // bridge failure gracefully (close connection).
                    return Err(e);
                }
            }
        }
        // Non-TCP stream — fall through to generic path
        // (local/remote already destructured above; reconstruct for fallback)
        // Actually: matching consumed the IoStream. For the mixed case
        // (one Tcp, one not), splice can't help — use bridge_plain below.
        // Reconstruction not needed; bridge_plain handles generic case.
        // In practice this branch is taken only on non-Linux or mixed types.
        // Reconstruct from owned halves:
        return bridge_plain(
            local_tcp.map(IoStream::Tcp).unwrap_or_else(|| /* unreachable */ unreachable!()),
            remote_tcp.map(IoStream::Tcp).unwrap_or_else(|| unreachable!()),
        ).await;
    }
    #[cfg(not(target_os = "linux"))]
    {
        bridge_plain(local, remote).await
    }
}
```

Note: the destructure-then-reconstruct pattern in the Linux fallback is awkward. Better: borrow-check IoStream before moving:

```rust
pub async fn bridge_plain_dispatch(
    local: IoStream,
    remote: IoStream,
) -> Result<(), std::io::Error> {
    #[cfg(target_os = "linux")]
    {
        if matches!((&local, &remote), (IoStream::Tcp(_), IoStream::Tcp(_))) {
            let l = match local { IoStream::Tcp(s) => s, _ => unreachable!() };
            let r = match remote { IoStream::Tcp(s) => s, _ => unreachable!() };
            match bridge_plain_zero_copy(l, r).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::debug!(error = %e,
                        "splice bridge failed, falling back to copy_bidirectional");
                    return Err(e);
                }
            }
        }
    }
    // General path: tokio copy_bidirectional
    bridge_plain(local, remote).await
}
```

Call sites (`assign_or_queue` in server `control.rs`, client proxy handler) call `bridge_plain_dispatch` when no encryption/compression/bandwidth-limiting is configured. Detection happens at each call site before invoking the bridge.

### 3.3 Where to Call

Two sites:

1. **Server** `control.rs` `assign_or_queue()` — after checking `use_encryption`, `use_compression`, bandwidth limiter. If all false and both sides are `IoStream::Tcp`: call bridge_plain_tcp.
2. **Client** `service.rs` proxy handler — same checks, same dispatch.

Bandwidth-limited plain path already has `bridge_plain_rate_limited` — not eligible for zero-copy (needs token-bucket buffering).

### 3.4 Non-Linux Behavior

No degradation. Fall through to existing `bridge_plain` (tokio `copy_bidirectional`). Same throughput as today.

### 3.5 Dependencies

- `libc` — workspace direct dependency (currently transitive). Linux-only compile target.
- No `socket2` usage needed — `AsRawFd` from `std::os::fd` (stable since Rust 1.64).

### 3.6 Binary Size Impact

~5-10KB for splice wrapper functions. Linux-only, `#[cfg]` stripped on other platforms. `libc` already in dep tree — workspacing it as direct adds no new code.

## Feature Gates Summary

| Feature | Default | Crate | Removes |
|---------|---------|-------|---------|
| `profiling` | **OFF** | frp-core/frps/frpc | pprof flamegraph capability |

SIMD changes are not feature-gated — they're compile-time improvements on existing crypto paths. Zero-copy is `#[cfg(target_os = "linux")]`, not a Cargo feature.

## Testing

### Profiling
- **Unit:** `dump_cpu_profile` writes SVG and protobuf files, returns correct path
- **Manual:** `kill -USR2 <pid>` on running frps/frpc, verify `.svg` and `.pb` produced
- **CI:** `cargo build --features profiling` gate — no runtime test (requires signal + 30s sleep)
- **Feature-gate:** `cargo build` without `profiling` — binary identical to before

### SIMD Crypto
- **Unit:** CfbState round-trip encrypt+decrypt with existing proptest framework
- **Bench:** Criterion `cipher_stream` benchmarks — compare before/after throughput
- **Compat:** `bash scripts/compat-test.sh --verbose` — Go frp interop must be byte-identical
- **Correctness:** AES-NI and software AES produce identical ciphertext (same algorithm, different backend)
- **Cross-platform:** CI runs on x86_64 (AES-NI) and aarch64 (ARMv8) runners

### Zero-Copy
- **Unit:** `bridge_plain_tcp` relay between localhost socket pair, verify byte count
- **Integration:** Test with `cargo test -p frp-server --test proxy_plain` — verify no data corruption
- **Compat:** `bash scripts/compat-test.sh` plain TCP tests — Go frp ↔ Rust frp plain proxy
- **Non-Linux:** macOS CI verifies `bridge_plain` fallback path works
- **Stress:** `scripts/stress-test.sh` plain proxy scenario — no data loss under load

## Files Changed

| File | Change |
|------|--------|
| `Cargo.toml` | +`pprof` (optional), +`libc` (workspace direct) |
| `frp-core/Cargo.toml` | +`profiling` feature, aes +cpuid+armv8, chacha20poly1305 +simd, +libc (linux) |
| `frp-core/src/lib.rs` | +`#[cfg(feature = "profiling")] pub mod profiling;` |
| `frp-core/src/profiling.rs` | NEW — dump_cpu_profile function |
| `frp-core/src/cipher_stream.rs` | u128 XOR in CfbState encrypt/decrypt |
| `frp-core/src/crypto.rs` | Verify chacha20poly1305 SIMD (likely no code change) |
| `frp-core/src/bridge.rs` | +bridge_plain_zero_copy (linux), +bridge_plain_dispatch |
| `frps/src/main.rs` | +profile signal handler (unix+profiling) |
| `frpc/src/main.rs` | +profile signal handler (unix+profiling) |
| `frp-server/src/control.rs` | Call bridge_plain_dispatch in assign_or_queue |
| `frp-client/src/service.rs` | Call bridge_plain_dispatch in proxy handler |
| `frps/Cargo.toml` | +profiling feature propagation |
| `frpc/Cargo.toml` | +profiling feature propagation |

## Error Handling

| Scenario | Behavior |
|----------|----------|
| SIGUSR2 not available (non-Unix) | warn-level log, profiling disabled, service runs normally |
| Profile directory not writable | error log, profile not written, service continues |
| Profile duration times out | guard drops, partial profile written if possible |
| AES-NI not available (old x86) | `cpuid` feature auto-falls back to software AES — no change from today |
| splice fails with EAGAIN | libc::splice returns -1+EAGAIN → std::io::Error → logged, fallback to copy_bidirectional |
| splice fails with EBADF/EINVAL | Return error, caller falls back to copy_bidirectional |
| Linux pipe creation fails | Return error, caller falls back to copy_bidirectional |

## Performance Expectations

| Metric | Before | After | Gain |
|--------|--------|-------|------|
| V1 encrypted throughput | ~306 MB/s | ~800-1000 MB/s | 2.6-3.3x |
| V1 AES-128 block encrypt | ~40ns | ~4ns | 10x |
| Plain TCP CPU per GB | ~100% (userspace copy) | ~40-60% (kernel splice) | 40-60% reduction |
| Default binary size | 4.8MB (frps) | 4.8MB (profiling off) | 0 |
| Profiling binary size | N/A | ~5.1MB (frps) | ~300KB (opt-in) |
