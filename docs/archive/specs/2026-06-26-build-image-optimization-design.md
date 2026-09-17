# Build & Image Optimization — Design Spec

**Goal:** Shrink release binary to sub-1.5MB and produce distroless Docker image ~8-10MB.

**Current state:** frpc 2.4MB, no Dockerfile, release profile already aggressive (`opt-level=z`, `lto=fat`, `strip=symbols`, `panic=abort`, `codegen-units=1`).

---

## 1. Binary Size Optimization

### 1.1 Dependency Audit

Run `cargo udeps` to find unused crates. Remove from workspace `Cargo.toml`.

**Known candidates:**
- `kcp` / `quic` modules — if removed in code cleanup, any associated deps drop
- `tokio` `full` feature — replace with minimal feature set
- `native-tls` / `rustls` — only one needed, verify both aren't compiled

### 1.2 Tokio Feature Slimming

Current: `tokio = { version = "1", features = ["full"] }` (from Cargo.toml)
`full` pulls in: `rt-multi-thread, macros, sync, time, net, fs, io-util, process, signal`.

**Replace with minimal:**
```toml
tokio = { version = "1", features = [
    "net",
    "io-util",
    "rt-multi-thread",
    "sync",
    "macros",
    "time",
] }
```

Removes: `fs`, `process`, `signal` — saves ~50-100KB.

### 1.3 TLS Crate Dedup

Check if both `native-tls` and `rustls` are in dependency tree.
If only one TLS backend is used at runtime, remove the other from `Cargo.toml`.

**Check:**
```bash
cargo tree -p frpc --invert native-tls 2>/dev/null
cargo tree -p frpc --invert rustls 2>/dev/null
```

If both present, pick one and remove the other's feature flag.

### 1.4 Remove KCP/QUIC Modules

If dead code removal (spec 1) deletes `kcp.rs` and `quic.rs`:
- Remove `pub mod kcp;` and `pub mod quic;` from `frp-core/src/lib.rs`
- Remove `IoStream::Kcp` and `IoStream::Quic` variants + match arms in `transport.rs`
- Remove any KCP/QUIC-related dependencies from `Cargo.toml`

Estimated savings: 50-100KB binary + fewer deps to compile.

### 1.5 UPX Compression

Add to release workflow (manual or CI):

```bash
# Install UPX (macOS: brew install upx, Linux: apt install upx-ucl)
upx --best --lzma target/release/frps
upx --best --lzma target/release/frpc
```

**Expected:** 2.4MB → ~1.0-1.2MB per binary. ~50-60% reduction.
**Trade-off:** ~50ms decompress at startup, negligible for long-running daemons.
**Risk:** Rare false positives from antivirus (UPX-packed binaries). Document this.

### 1.6 Cargo.toml Release Profile (already optimal)

Current settings kept as-is:
```toml
[profile.release]
opt-level = "z"
lto = "fat"
codegen-units = 1
strip = "symbols"
panic = "abort"
```

`strip = "symbols"` could become `strip = true` (stable since Rust 1.79) for full
debuginfo + symbol stripping, but `"symbols"` already covers the main savings.

---

## 2. Docker Image

### 2.1 Multi-stage Build with Distroless

```dockerfile
# syntax=docker/dockerfile:1

# ── Stage 1: Build ────────────────────────────────────────────
FROM rust:1.91-alpine AS builder

RUN apk add --no-cache musl-dev perl make upx

WORKDIR /app

# Cache deps (separate layer)
COPY Cargo.toml Cargo.lock ./
COPY frp-core/Cargo.toml frp-core/
COPY frp-server/Cargo.toml frp-server/
COPY frp-client/Cargo.toml frp-client/
RUN mkdir -p frp-core/src frp-server/src frp-client/src && \
    echo 'fn main() {}' > frp-core/src/lib.rs && \
    echo 'fn main() {}' > frp-server/src/main.rs && \
    echo 'fn main() {}' > frp-client/src/main.rs && \
    cargo build --release && \
    rm -rf frp-core/src frp-server/src frp-client/src

# Build real source
COPY frp-core/src frp-core/src/
COPY frp-server/src frp-server/src/
COPY frp-client/src frp-client/src/
RUN cargo build --release --bin frps --bin frpc

# UPX compress
RUN upx --best --lzma target/release/frps target/release/frpc

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:latest

COPY --from=builder /app/target/release/frps /usr/local/bin/frps
COPY --from=builder /app/target/release/frpc /usr/local/bin/frpc

# Default entrypoint: frps (override for frpc)
ENTRYPOINT ["/usr/local/bin/frps"]
CMD ["-c", "/etc/frp/frps.toml"]
```

### 2.2 Image Size Estimate

| Layer | Size |
|-------|------|
| distroless/static-debian12 base | ~3 MB |
| frps (UPX compressed) | ~1.2 MB |
| frpc (UPX compressed) | ~1.0 MB |
| **Total** | **~5.2 MB** |

Without UPX: ~7.5 MB. Both versions ship two binaries in one image.

### 2.3 Alternative: Single-binary Images

For even smaller per-role images, two Dockerfiles:

```dockerfile
# Dockerfile.frps — frps only, ~4.2 MB
FROM gcr.io/distroless/static-debian12:latest
COPY --from=builder /app/target/release/frps /frps
ENTRYPOINT ["/frps"]

# Dockerfile.frpc — frpc only, ~4.0 MB
FROM gcr.io/distroless/static-debian12:latest
COPY --from=builder /app/target/release/frpc /frpc
ENTRYPOINT ["/frpc"]
```

**Decision:** Ship combined image (simpler CI, one tag). Users who want single-binary
can override entrypoint: `docker run --entrypoint /usr/local/bin/frpc ...`

### 2.4 Config Mount

Image expects config at `/etc/frp/frps.toml`. User mounts:

```bash
docker run -v ./frps.toml:/etc/frp/frps.toml frp:latest
```

No config baked into image — clean separation.

---

## 3. CI Integration (Optional)

Add to `.github/workflows/release.yml` or similar:

```yaml
- name: UPX compress
  run: |
    upx --best --lzma target/release/frps
    upx --best --lzma target/release/frpc

- name: Build Docker image
  run: |
    docker build -t frp:latest .
    docker tag frp:latest ghcr.io/viogus/frp:latest
```

---

## 4. Testing & Verification

| Check | Command | Expected |
|-------|---------|----------|
| Binary size | `ls -lh target/release/frpc target/release/frps` | < 1.5 MB each |
| UPX'd size | `upx --best --lzma target/release/frpc && ls -lh target/release/frpc` | < 1.2 MB |
| Binary runs | `./target/release/frpc --version` | prints version |
| Docker build | `docker build -t frp .` | success |
| Docker size | `docker images frp --format '{{.Size}}'` | < 10 MB |
| Docker run | `docker run --rm frp --version` | prints version |
| Test suite | `cargo test --workspace` | all pass |

---

## 5. Files Summary

| File | Action | Lines |
|------|--------|-------|
| `Cargo.toml` | Modify | ~10 (tokio features, remove unused deps) |
| `frp-core/src/lib.rs` | Modify | ~2 (remove kcp/quic mod if dead) |
| `frp-core/src/transport.rs` | Modify | ~20 (remove Kcp/Quic variants if dead) |
| `Dockerfile` | Create | ~35 |
| `.dockerignore` | Create | ~10 |
| `frp-core/src/kcp.rs` | Delete | -333 (if dead) |
| `frp-core/src/quic.rs` | Delete | -182 (if dead) |
| **Total** | | **~70 new, ~515 deleted** |
