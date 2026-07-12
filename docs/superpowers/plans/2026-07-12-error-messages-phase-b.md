# Error Messages & Exit Codes (Phase B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix top-5 error message pain points: config parse context, empty-token security gate, unknown transport hard error, structured exit codes, unknown-field suggestions.

**Architecture:** Five independent fixes touching frp-core (auth, config, lib), frp-client (service), frps (main), frpc (main). Each fix is self-contained and can be merged independently. No new dependencies.

**Tech Stack:** Rust, thiserror, toml, serde_json, bpaf

## Global Constraints

- No new crate dependencies
- All changes backward-compatible (config files that worked before still work)
- Exit codes: 1=runtime, 2=config, 3=auth, 4=bind
- Empty token is now a hard error at startup (breaking change from Go frp compat)

---

### Task 1: Add exit code constants to `Error` enum

**Files:**
- Modify: `frp-core/src/lib.rs:35-55`

**Interfaces:**
- Produces: `Error::exit_code(&self) -> i32`, `pub const EXIT_RUNTIME: i32 = 1;`, `pub const EXIT_CONFIG: i32 = 2;`, `pub const EXIT_AUTH: i32 = 3;`, `pub const EXIT_BIND: i32 = 4;`

- [ ] **Step 1: Add exit code constants and method**

Edit `frp-core/src/lib.rs`, replace the Error enum block (lines 35-55):

```rust
use thiserror::Error;

/// Exit codes for process termination.
/// Mirrored in frps/frpc main.rs — keep in sync.
pub const EXIT_RUNTIME: i32 = 1;   // connection lost, I/O error, unexpected
pub const EXIT_CONFIG: i32 = 2;    // bad config file, unknown field, invalid value
pub const EXIT_AUTH: i32 = 3;      // bad token, OIDC failure
pub const EXIT_BIND: i32 = 4;      // port in use, permission denied

#[derive(Error, Debug)]
pub enum Error {
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("Auth error: {0}")]
    Auth(String),
    #[error("Config error: {0}")]
    Config(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Map each error variant to a process exit code.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Config(_) => EXIT_CONFIG,
            Error::Auth(_) => EXIT_AUTH,
            Error::Io(e) if e.kind() == std::io::ErrorKind::AddrInUse
                || e.kind() == std::io::ErrorKind::PermissionDenied => EXIT_BIND,
            _ => EXIT_RUNTIME,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
```

- [ ] **Step 2: Build check**

```bash
cargo build -p frp-core 2>&1 | tail -5
```

Expected: compiles clean, no warnings.

- [ ] **Step 3: Commit**

```bash
git add frp-core/src/lib.rs
git commit -m "feat(error): add exit_code() method and EXIT_* constants to Error enum"
```

---

### Task 2: Use exit codes in frps main.rs

**Files:**
- Modify: `frps/src/main.rs` (all `process::exit(1)` sites)

**Interfaces:**
- Consumes: `frp_core::{EXIT_RUNTIME, EXIT_CONFIG, EXIT_AUTH, EXIT_BIND}`, `Error::exit_code()`

- [ ] **Step 1: Replace all `process::exit(1)` with appropriate exit codes in `frps/src/main.rs`**

Read the file and replace each `process::exit(1)`:

Line ~201 (`collect_config_files` error — config):
```rust
// Before:
process::exit(1);
// After:
process::exit(frp_core::EXIT_CONFIG);
```

Line ~206 (no config files — config):
```rust
// Before:
process::exit(1);
// After:
process::exit(frp_core::EXIT_CONFIG);
```

Line ~241 (all services failed — config):
```rust
// Before:
process::exit(1);
// After:
process::exit(frp_core::EXIT_CONFIG);
```

Line ~248 (task join error — runtime):
```rust
// Before:
process::exit(1);
// After:
process::exit(frp_core::EXIT_RUNTIME);
```

Single-config mode (check for config load error):
```rust
// Before (config load error → exit 1):
process::exit(1);
// After:
process::exit(frp_core::EXIT_CONFIG);
```

Single-config mode (Service::new error — could be bind):
```rust
// Before:
process::exit(1);
// After:
process::exit(frp_core::EXIT_BIND);
```

Single-config mode (service.run error — runtime):
```rust
// Before:
process::exit(1);
// After:
process::exit(frp_core::EXIT_RUNTIME);
```

- [ ] **Step 2: Build check**

```bash
cargo build -p frps 2>&1 | tail -5
```

Expected: compiles clean.

- [ ] **Step 3: Commit**

```bash
git add frps/src/main.rs
git commit -m "feat(frps): use structured exit codes (2=config, 3=auth, 4=bind, 1=runtime)"
```

---

### Task 3: Use exit codes in frpc main.rs

**Files:**
- Modify: `frpc/src/main.rs` (all `process::exit(1)` sites)

**Interfaces:**
- Consumes: `frp_core::{EXIT_RUNTIME, EXIT_CONFIG, EXIT_AUTH, EXIT_BIND}`

- [ ] **Step 1: Replace all `process::exit(1)` with appropriate exit codes in `frpc/src/main.rs`**

Config dir mode — `collect_config_files` error (line ~233):
```rust
// Before:
process::exit(1);
// After:
process::exit(frp_core::EXIT_CONFIG);
```

Config dir mode — no config files (line ~238):
```rust
// Before:
process::exit(1);
// After:
process::exit(frp_core::EXIT_CONFIG);
```

Config dir mode — all services failed (line ~272):
```rust
// Before:
process::exit(1);
// After:
process::exit(frp_core::EXIT_CONFIG);
```

Single config mode — `load_client_config` error (line ~288):
```rust
// Before:
process::exit(1);
// After:
process::exit(frp_core::EXIT_CONFIG);
```

Single config mode — `Service::new` error (line ~299):
```rust
// Before:
process::exit(1);
// After:
process::exit(frp_core::EXIT_BIND);
```

Single config mode — `service.run()` error (line ~309):
```rust
// Before (after run error):
process::exit(1);
// After:
process::exit(frp_core::EXIT_RUNTIME);
```

- [ ] **Step 2: Build check**

```bash
cargo build -p frpc 2>&1 | tail -5
```

Expected: compiles clean.

- [ ] **Step 3: Commit**

```bash
git add frpc/src/main.rs
git commit -m "feat(frpc): use structured exit codes (2=config, 3=auth, 4=bind, 1=runtime)"
```

---

### Task 4: Config parse errors — add file path context

**Files:**
- Modify: `frp-core/src/config.rs:997-1015` (load_config_from_file)
- Modify: `frp-core/src/config.rs:917-930` (load_server_config_from_str, load_client_config_from_str)

**Interfaces:**
- Produces: errors now include file path ("{path}: TOML parse error: {e}")

- [ ] **Step 1: Add path context to `load_config_from_file`**

Replace lines 1003-1013:

```rust
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("{path}: failed to read config file: {e}"))?;
    let format = detect_format(path);
    let mut value: toml::Value = parse_to_toml_value(&content, format)
        .map_err(|e| format!("{path}: parse error: {e}"))?;
    let base_dir = Path::new(path).parent().unwrap_or(Path::new("."));
    process_includes(&mut value, base_dir)?;
    normalize(&mut value);
    if strict_config {
        run_strict_check(&value, &known_keys(), path)?;
    }
    let json_value = toml_to_json(value);
    let cfg: C = serde_json::from_value(json_value)
        .map_err(|e| format!("{path}: config validation error: {e}"))?;
    Ok(cfg)
```

- [ ] **Step 2: Add path context to `load_server_config_from_str` / `load_client_config_from_str`**

The `_from_str` variants don't have a path parameter. They are used by tests and programmatic callers. Add a generic context:

```rust
pub fn load_server_config_from_str(content: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut value: toml::Value = toml::from_str(content)
        .map_err(|e| format!("TOML parse error: {e}"))?;
    normalize_server_config(&mut value);
    let json_value = toml_to_json(value);
    let cfg: ServerConfig = serde_json::from_value(json_value)
        .map_err(|e| format!("config validation error: {e}"))?;
    Ok(cfg)
}

pub fn load_client_config_from_str(content: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut value: toml::Value = toml::from_str(content)
        .map_err(|e| format!("TOML parse error: {e}"))?;
    normalize_client_config(&mut value);
    let cfg: ClientConfig = serde_json::from_value(toml_to_json(value))
        .map_err(|e| format!("config validation error: {e}"))?;
    Ok(cfg)
}
```

- [ ] **Step 3: Build and run existing tests**

```bash
cargo test -p frp-core -- config 2>&1 | tail -20
```

Expected: all config tests pass (test error messages may change slightly — verify no unexpected failures).

- [ ] **Step 4: Commit**

```bash
git add frp-core/src/config.rs
git commit -m "fix(config): add file path context to config parse and validation errors"
```

---

### Task 5: Empty token security gate — hard error at startup

**Files:**
- Modify: `frp-core/src/auth.rs:124-131`
- Verify: `frp-server/src/service.rs` (check_startup call)

**Interfaces:**
- Produces: empty token + Token auth → `Err` at login validation

- [ ] **Step 1: Check that `check_startup` is called in all server start paths**

```bash
grep -n 'check_startup' frp-server/src/service.rs
```

Expected: at least one call site. If none found, add `auth_cfg.check_startup()?;` in `Service::new()`.

- [ ] **Step 2: Replace empty-token fallback with hard error in `auth.rs`**

Replace lines 125-131:

```rust
    pub fn validate_login(&self, privilege_key: Option<&str>, timestamp: Option<i64>) -> Result<String, String> {
        if self.token.is_empty() && self.method == AuthMethod::Token {
            return Err(
                "authentication token is empty. When auth.method = 'token', \
                 you must set auth.token in the config file or use the --token CLI flag. \
                 An empty token would accept ALL connections without authentication."
                    .to_string(),
            );
        }

        let key = privilege_key.unwrap_or("");
```

- [ ] **Step 3: Check `check_startup` also gates on empty token**

Read `auth.rs` for the `check_startup` method and ensure it also returns Err for empty token:

```bash
grep -n -A 15 'fn check_startup' frp-core/src/auth.rs
```

If `check_startup` exists and checks empty token, it stays as-is. If it doesn't exist, add it:

```rust
impl AuthConfig {
    /// Called at server startup to reject dangerous configurations.
    pub fn check_startup(&self) -> Result<(), String> {
        if self.token.is_empty() && self.method == AuthMethod::Token {
            return Err(
                "authentication token is empty with token auth method. \
                 Set auth.token in config or use --token CLI flag.".to_string(),
            );
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Build and test**

```bash
cargo build --workspace 2>&1 | tail -10
cargo test -p frp-core -- auth 2>&1 | tail -20
```

Expected: compiles. Auth tests pass (may need to update tests that relied on empty-token acceptance).

- [ ] **Step 5: Check for test failures from empty-token acceptance**

```bash
cargo test --workspace 2>&1 | grep -E 'FAILED|test result'
```

If any tests relied on empty token being accepted, update them to set a real token.

- [ ] **Step 6: Commit**

```bash
git add frp-core/src/auth.rs
# If check_startup added to service.rs:
# git add frp-server/src/service.rs
git commit -m "fix(auth): hard error on empty token with token auth method"
```

---

### Task 6: Unknown transport protocol — hard error instead of silent TCP fallback

**Files:**
- Modify: `frp-client/src/service.rs:347-353`

**Interfaces:**
- Produces: returns `Err` with valid transport variants listed

- [ ] **Step 1: Replace warn+fallback with Err**

Replace lines 347-353:

```rust
        let protocol: TransportProtocol = match self.cfg.transport_protocol.parse() {
            Ok(p) => p,
            Err(_) => {
                return Err(format!(
                    "unknown transport protocol '{}'. Valid transports: tcp, kcp, quic, websocket",
                    self.cfg.transport_protocol
                ).into());
            }
        };
```

Remove the now-unused `warn` import if `warn` was only used here:
```bash
grep -n 'use tracing.*warn' frp-client/src/service.rs
```

If `warn` is used elsewhere in the file, leave the import.

- [ ] **Step 2: Update the return type if needed**

The function `run()` already returns `Result<(), Box<dyn std::error::Error>>`, and `format!(...).into()` produces `Box<dyn std::error::Error>`. No signature change needed.

- [ ] **Step 3: Build and test**

```bash
cargo build -p frp-client 2>&1 | tail -10
cargo test -p frp-client 2>&1 | tail -10
```

Expected: compiles. Tests pass.

- [ ] **Step 4: Commit**

```bash
git add frp-client/src/service.rs
git commit -m "fix(client): hard error on unknown transport protocol instead of silent TCP fallback"
```

---

### Task 7: Unknown field suggestions via Levenshtein distance

**Files:**
- Modify: `frp-core/src/config.rs:1522-1549`

**Interfaces:**
- Produces: `"unknown field 'serverAddr' — did you mean 'server_addr'?"`

- [ ] **Step 1: Add Levenshtein distance helper function**

Add this function just above `check_strict` (before line 1522):

```rust
/// Compute Levenshtein distance between two strings.
/// Used to suggest corrections for unknown config fields.
fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let n = a_chars.len();
    let m = b_chars.len();
    let mut prev = (0..=m).collect::<Vec<_>>();
    let mut curr = vec![0; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1)
                .min(curr[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}
```

- [ ] **Step 2: Add suggestion logic to `check_strict`**

Replace the error push in `check_strict` (lines 1542-1544):

```rust
                errors.push(format!(
                    "unknown field \"{}\" in config file {}", full_key, config_path
                ));
```

With suggestion logic:

```rust
                let mut msg = format!(
                    "unknown field \"{}\" in config file {}", full_key, config_path
                );
                // Suggest closest known key if within edit distance 3
                let mut best: Option<(&str, usize)> = None;
                for known_key in known.iter() {
                    let d = levenshtein(key, known_key);
                    if d <= 3 && (best.is_none() || d < best.unwrap().1) {
                        best = Some((known_key, d));
                    }
                }
                if let Some((suggestion, _)) = best {
                    msg.push_str(&format!(" — did you mean '{}'?", suggestion));
                }
                errors.push(msg);
```

- [ ] **Step 3: Write unit test**

Add to the `mod tests` block at the bottom of config.rs:

```rust
    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein("server_addr", "serverAddr"), 1); // case + underscore
        assert_eq!(levenshtein("bind_port", "bindPort"), 1);
        assert_eq!(levenshtein("token", "tokens"), 1);
        assert_eq!(levenshtein("abc", "xyz"), 3);
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("a", ""), 1);
    }

    #[test]
    fn test_unknown_field_suggestion() {
        // Build a simple toml table with an unknown key
        let toml_str = "[auth]\ntoken = \"test\"\nserverAddr = \"1.2.3.4\"\n";
        let value: toml::Value = toml::from_str(toml_str).unwrap();
        let known: std::collections::HashSet<&str> =
            ["token", "server_addr"].iter().copied().collect();
        let errors = check_strict(
            value.as_table().unwrap(),
            &known,
            "",
            "test.toml",
        );
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("did you mean 'server_addr'"));
    }
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p frp-core -- config 2>&1 | tail -30
```

Expected: `test_levenshtein` and `test_unknown_field_suggestion` pass. All existing config tests pass.

- [ ] **Step 5: Commit**

```bash
git add frp-core/src/config.rs
git commit -m "feat(config): suggest closest known field name for unknown config keys (Levenshtein)"
```

---

### Task 8: Integration test — verify all fixes work together

**Files:**
- Create: test config files for each error case (temporary, not committed)
- Run: existing compat tests to verify no regressions

- [ ] **Step 1: Test exit codes**

```bash
# Config error → exit 2
cargo run --bin frps -- -c /nonexistent/config.toml 2>&1; echo "exit: $?"
# Expected: error message with path, exit code 2

# Empty token should fail at startup (need a minimal config with empty token)
```

- [ ] **Step 2: Test config parse error with path**

```bash
echo "invalid toml [[" > /tmp/bad.toml
cargo run --bin frps -- -c /tmp/bad.toml 2>&1; echo "exit: $?"
# Expected: "/tmp/bad.toml: parse error: ..." in output, exit code 2
```

- [ ] **Step 3: Run full compat test suite**

```bash
bash scripts/compat-test.sh --ci 2>&1 | tail -20
```

Expected: 55 passed, 0 failed. No regressions.

- [ ] **Step 4: Commit workspace-level test verification**

```bash
git add -A
git commit -m "test: verify Phase B error fixes — exit codes, config context, suggestions"
```

---

## Review Gates

After all tasks complete:

1. **Compat tests**: `bash scripts/compat-test.sh --ci` — 55/55 pass
2. **Workspace build**: `cargo build --workspace` — clean
3. **Clippy**: `cargo clippy --workspace` — no new warnings
4. **Tests**: `cargo test --workspace` — all pass
