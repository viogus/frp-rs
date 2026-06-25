# Build & Image Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Shrink release binary to sub-1.5MB and produce distroless Docker image ~5-8MB.

**Architecture:** Three phases: slim Cargo.toml (tokio features, dedup TLS, remove unused deps) → UPX compression → multi-stage distroless Dockerfile. Binary size measured after each phase. Each task is self-contained and verifiable.

**Tech Stack:** Rust 1.91+, cargo-udeps, UPX, Docker multi-stage with distroless/static.

---

### Task 1: Dependency Audit and Cargo.toml Slimming

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `frp-core/Cargo.toml`, `frp-server/Cargo.toml`, `frp-client/Cargo.toml` (if needed)

- [ ] **Step 1: Run cargo-udeps to find unused crates**

```bash
cargo udeps --release 2>&1 | head -40
```

If `cargo-udeps` not installed:
```bash
cargo install cargo-udeps
```

Expected: list of unused dependencies. Remove any from workspace or crate Cargo.toml files.

- [ ] **Step 2: Slim tokio features**

In workspace `Cargo.toml`, find the `tokio` dependency and replace `features = ["full"]`:

```toml
# Before:
tokio = { version = "1", features = ["full"] }

# After:
tokio = { version = "1", features = [
    "net",
    "io-util",
    "rt-multi-thread",
    "sync",
    "macros",
    "time",
] }
```

- [ ] **Step 3: Check TLS crate dedup**

```bash
cargo tree -p frpc --invert native-tls 2>/dev/null | head -5
cargo tree -p frpc --invert rustls 2>/dev/null | head -5
cargo tree -p frps --invert native-tls 2>/dev/null | head -5
cargo tree -p frps --invert rustls 2>/dev/null | head -5
```

If both TLS backends are in the tree, check which one is actually used at runtime. Remove the unused one's feature flag from Cargo.toml.

If only `native-tls` is used (likely — tokio-tls), ensure `rustls` is not pulled in:
```bash
cargo tree -p frpc --invert rustls 2>/dev/null
```
If `rustls` appears but is unused, add it to root Cargo.toml with `optional = true` or remove the dependency that pulls it in.

- [ ] **Step 4: Remove KCP/QUIC dependencies if modules deleted**

If the code optimization plan removed `kcp.rs` and `quic.rs`, check for associated deps in Cargo.toml files and remove them. Check:

```bash
grep -i 'kcp\|quic' Cargo.toml frp-core/Cargo.toml frp-server/Cargo.toml frp-client/Cargo.toml
```

Remove any KCP/QUIC-specific dependencies found.

- [ ] **Step 5: Build release and measure baseline**

```bash
cargo build --release --bin frps --bin frpc
ls -lh target/release/frps target/release/frpc
```

Record sizes. Expected reduction from 2.4MB baseline.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml frp-core/Cargo.toml frp-server/Cargo.toml frp-client/Cargo.toml
git commit -m "build: slim tokio features, remove unused dependencies"
```

---

### Task 2: UPX Binary Compression

**Files:**
- No code changes. Release workflow addition.

- [ ] **Step 1: Install UPX**

```bash
# macOS
brew install upx

# Linux
sudo apt install upx-ucl
```

- [ ] **Step 2: Compress release binaries**

```bash
upx --best --lzma target/release/frps
upx --best --lzma target/release/frpc
ls -lh target/release/frps target/release/frpc
```

Expected: frps ~1.0-1.2MB, frpc ~0.8-1.0MB (from 2.4MB each).

- [ ] **Step 3: Verify compressed binaries run**

```bash
./target/release/frps --version
./target/release/frpc --version
```

Expected: both print version string without crash. UPX decompression is transparent.

- [ ] **Step 4: Add UPX to release profile notes**

Add a comment in `Cargo.toml` above `[profile.release]`:

```toml
# Release profile: slim, LTO, single codegen unit, stripped symbols, abort on panic.
# After cargo build --release, compress further with:
#   upx --best --lzma target/release/frps target/release/frpc
```

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml
git commit -m "build: add UPX compression recipe to release profile"
```

---

### Task 3: Dockerfile — Multi-stage Distroless

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`

- [ ] **Step 1: Create .dockerignore**

Create `.dockerignore`:

```
# Rust build artifacts
target/
.cargo/

# Git
.git/
.gitignore

# IDE
.vscode/
.idea/

# Docs (not needed in container)
docs/

# Test fixtures and temp files
*.swp
*.swo
*~
```

- [ ] **Step 2: Create Dockerfile**

Create `Dockerfile`:

```dockerfile
# syntax=docker/dockerfile:1

# ── Stage 1: Build ────────────────────────────────────────────
FROM rust:1.91-alpine AS builder

RUN apk add --no-cache musl-dev perl make upx

WORKDIR /app

# Cache dependencies (separate layer for faster rebuilds)
COPY Cargo.toml Cargo.lock ./
COPY frp-core/Cargo.toml    frp-core/
COPY frp-server/Cargo.toml  frp-server/
COPY frp-client/Cargo.toml  frp-client/

RUN mkdir -p frp-core/src frp-server/src frp-client/src && \
    echo 'pub fn main() {}' > frp-core/src/lib.rs && \
    echo 'fn main() {}'     > frp-server/src/main.rs && \
    echo 'fn main() {}'     > frp-client/src/main.rs && \
    cargo build --release --bin frps --bin frpc && \
    rm -rf frp-core/src frp-server/src frp-client/src

# Build real source
COPY frp-core/src   frp-core/src/
COPY frp-server/src frp-server/src/
COPY frp-client/src frp-client/src/

RUN cargo build --release --bin frps --bin frpc && \
    upx --best --lzma target/release/frps target/release/frpc

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:latest

COPY --from=builder /app/target/release/frps /usr/local/bin/frps
COPY --from=builder /app/target/release/frpc /usr/local/bin/frpc

# Default entrypoint: frps (override for frpc)
ENTRYPOINT ["/usr/local/bin/frps"]
CMD ["-c", "/etc/frp/frps.toml"]
```

- [ ] **Step 3: Build Docker image**

```bash
docker build -t frp:latest .
```

Expected: builds successfully.

- [ ] **Step 4: Verify image size**

```bash
docker images frp:latest --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}'
```

Expected: < 10 MB (target ~5-8 MB with UPX).

- [ ] **Step 5: Verify image runs**

```bash
docker run --rm frp:latest --version
```

Expected: prints frps version. (No config, so it errors after version check — that's fine.)

- [ ] **Step 6: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "build: add multi-stage distroless Dockerfile"
```

---

### Task 4: Final Verification

**Files:**
- All modified files

- [ ] **Step 1: Measure binary sizes**

```bash
ls -lh target/release/frps target/release/frpc
```

Expected: < 1.5 MB each (before UPX), < 1.2 MB (after UPX).

- [ ] **Step 2: Verify compressed binaries run**

```bash
./target/release/frps --version
./target/release/frpc --version
```

Expected: both print version string.

- [ ] **Step 3: Test suite**

```bash
cargo test --workspace
cargo clippy --workspace
```

Expected: all pass, clippy clean.

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore: final build/image optimization verification"
```
