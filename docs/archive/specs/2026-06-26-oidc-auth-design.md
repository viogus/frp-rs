# OIDC Authentication Design

## Context

frp-rs currently implements only token (MD5) authentication. Go frp v0.69.1 supports
both `token` and `oidc` auth methods. This spec covers adding full OIDC support:
client-side `client_credentials` grant token fetching, server-side JWT verification
with JWKS key lookup, and per-session subject binding for subsequent heartbeats
and work connections.

## Scope

**In scope:**
- `client_credentials` OAuth2 grant (frpc fetches token, puts in privilege_key)
- Server JWT verification: RS256/ES256 signature, issuer, audience, expiry
- JWKS auto-discovery from issuer `/.well-known/openid-configuration`
- JWKS caching with 1-hour refresh
- Subject (sub claim) recording at login, verification on ping + NewWorkConn
- Config: `[auth]` section on both server and client with Go frp parity
- `RUST_LOG=oidc=debug` for OIDC-specific diagnostics

**Out of scope (TODO markers left in code):**
- `authorization_code` flow (user-facing login)
- Custom `TokenSource` interface
- Custom HTTP client (TLS CA, proxy, insecure skip verify)
- Additional endpoint params (resource, etc.)

## Config

### Server (`frps.toml` — existing fields, no changes)

```toml
[auth]
method = "oidc"                              # "token" | "oidc"
token = ""                                   # required when method=token
oidc_issuer = "https://accounts.google.com"  # required when method=oidc
oidc_audience = "my-server"                  # required when method=oidc
oidc_skip_expiry = false                     # skip JWT exp check
oidc_skip_issuer = false                     # skip JWT iss check
```

### Client (`frpc.toml` — flat `token` backward compatible, new `[auth]` section)

```toml
# Backward compatible: flat token = auth.token
token = "my-shared-secret"

[auth]
method = "oidc"
token = ""                       # shared secret when method=token
oidc_client_id = "my-client"
oidc_client_secret = "xxx"
oidc_audience = "my-server"
oidc_token_endpoint = ""         # optional; auto-discovered from issuer if empty
oidc_scope = "openid"            # default: "openid"
additional_endpoint_params = ""  # TODO
oidc_issuer = ""                 # to discover token_endpoint if not set directly
```

### Config Parsing

- `ClientConfig.token` stays as-is for backward compat
- `AuthClientConfig` struct added with `method`, `token`, `oidc_*` fields
- `[auth]` section parsed → `AuthClientConfig`; if `[auth]` absent but `token` present → defaults to `method=token`
- `method="oidc"` requires `oidc_client_id` + `oidc_client_secret`; server `method="oidc"` requires `oidc_issuer` + `oidc_audience`

## Architecture

```
frp-core/src/auth.rs:
  ├── AuthConfig (existing, adds oidc_* fields)
  ├── AuthMethod (existing: Token | Oidc)
  ├── LoginOidcToken { subject, expiry }         // [NEW]
  ├── OidcClient                                  // [NEW]
  │   ├── new(client_id, secret, audience, token_endpoint?, scope)
  │   ├── set_login(&mut Login)   → Result<()>   // fetches token, sets privilege_key
  │   ├── set_ping(&mut Ping)     → Result<()>
  │   └── set_new_work_conn(&mut NewWorkConn) → Result<()>
  └── OidcVerifier                                // [NEW]
      ├── new(issuer, audience, skip_expiry, skip_issuer) → Result<Self>
      │   // Discovers JWKS URI, fetches keys
      ├── verify_login(token: &str) → Result<LoginOidcToken>
      │   // Decode JWT header, pick key by kid, verify sig + exp + iss + aud
      ├── verify_ping(token: &str, expected_sub: &str) → Result<()>
      └── verify_new_work_conn(token: &str, expected_sub: &str) → Result<()>

frp-core/src/config.rs:
  └── AuthClientConfig [NEW] — client-side [auth] section
  └── ClientConfig.auth: Option<AuthClientConfig> [NEW]

frp-client/src/service.rs:
  └── Service::new(): if auth.method == Oidc, create OidcClient
  └── login/ping/new_work_conn: call oidc_client.set_*() before sending

frp-server/src/service.rs:
  └── Service::new(): if auth.method == Oidc, create OidcVerifier (Arc)
  └── AppState: Option<Arc<OidcVerifier>> [NEW]

frp-server/src/control.rs:
  └── handle_control: login → verify_login, store subject
  └── handle_control: ping   → verify_ping with stored subject
  └── handle_work_conn_inner: → verify_new_work_conn with stored subject
```

## Dependencies

Add to workspace `Cargo.toml`:
```toml
jsonwebtoken = "9"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
```

`frp-core` already uses `serde_json`, `sha2`, `hex`, `md-5`, etc.

## Data Flow

### Login

```
frpc                                    frps
  |                                       |
  | OidcClient: POST token_endpoint       |
  |   client_id=...&client_secret=...     |
  |   grant_type=client_credentials       |
  |   scope=openid                        |
  |   audience=my-server                  |
  | ← access_token (JWT)                  |
  |                                       |
  | Login { privilege_key: access_token } |
  |-------------------------------------->|
  |                          OidcVerifier |
  |                          1. Decode JWT header → kid
  |                          2. Look up kid in cached JWKS
  |                          3. Verify signature with JWK
  |                          4. Check exp (if skip_expiry=false)
  |                          5. Check iss (if skip_issuer=false)
  |                          6. Check aud
  |                          7. Extract sub → LoginOidcToken { sub, exp }
  |                          8. Store subject keyed by run_id
  |                                       |
  |<-------- LoginResp { run_id } -------|
```

### Ping / NewWorkConn

```
frpc                                    frps
  |                                       |
  | OidcClient: fetch new token if        |
  |   cached token expired                |
  | (可复用上次 token，refresh 时重新拿)   |
  |                                       |
  | Ping { privilege_key: access_token }  |
  |-------------------------------------->|
  |                          OidcVerifier |
  |                          1. verify_login(token)  → get sub
  |                          2. assert sub == stored_subject(run_id)
  |                                       |
  |<-------- Pong ------------------------|
```

## JWKS Caching

```rust
struct OidcVerifier {
    issuer: String,
    audience: String,
    jwks: RwLock<CachedJwks>,
    skip_expiry: bool,
    skip_issuer: bool,
}

struct CachedJwks {
    keys: HashMap<String, jsonwebtoken::jwk::Jwk>,  // kid → key
    fetched_at: Instant,
    refresh_after: Duration,                         // 1 hour
}
```

- `new()`: GET `{issuer}/.well-known/openid-configuration` → extract `jwks_uri` → GET jwks → cache keys
- On verify: if `fetched_at + refresh_after < now` → background-refresh JWKS (don't block verification)
- If JWK for `kid` not found → fetch JWKS synchronously once, retry
- Max retries: 3, exponential backoff

## Error Handling

- Token endpoint unreachable → `Error::Auth("OIDC token endpoint unreachable: {url}")`
- JWKS fetch failed → `Error::Auth("OIDC JWKS fetch failed: {err}")`
- JWT signature invalid → `Error::Auth("OIDC token signature invalid")`
- Token expired → `Error::Auth("OIDC token expired")`
- Subject mismatch → `Error::Auth("OIDC subject mismatch: expected {expected}, got {got}")` — drop connection
- `kid` in JWT header not found in JWKS → re-fetch JWKS once, then fail if still missing

## Testing

### Unit Tests (`frp-core/src/auth.rs`)

- `test_oidc_token_validation_mock_jwks` — generate a JWT with a known RSA key, verify
- `test_oidc_token_wrong_audience` — reject
- `test_oidc_token_expired` — reject (unless skip_expiry)
- `test_oidc_subject_mismatch` — reject
- `test_jwks_key_lookup_by_kid` — correct key selection

### Integration Test

- `test_oidc_auth_e2e` — start frps with OIDC mode, mock token endpoint + JWKS endpoint (axum test server), frpc connects with OIDC client, verify login + ping succeed

## Behavior Parity with Go frp v0.69.1

| Aspect | Go frp | frp-rs (this spec) |
|--------|--------|---------------------|
| Grant type | client_credentials | client_credentials ✅ |
| Token endpoint | config or auto-discover | config or auto-discover ✅ |
| JWT verification | go-oidc (verify ID token) | jsonwebtoken ✅ |
| JWKS | auto from issuer | auto from issuer ✅ |
| Subject binding | yes (ping + nwc) | yes ✅ |
| Skip expiry check | config option | config option ✅ |
| Skip issuer check | config option | config option ✅ |
| Custom HTTP client | TLS CA, proxy, insecure | TODO |
| authorization_code | supported | TODO |
| TokenSource interface | pluggable | TODO |

## Files Modified

| File | Scope |
|------|-------|
| `Cargo.toml` | Add `jsonwebtoken`, `reqwest` to workspace deps |
| `frp-core/Cargo.toml` | Add `jsonwebtoken`, `reqwest` |
| `frp-core/src/auth.rs` | `OidcClient`, `OidcVerifier`, `LoginOidcToken`, `CachedJwks` |
| `frp-core/src/config.rs` | `AuthClientConfig`, wire into `ClientConfig` |
| `frp-client/src/service.rs` | Create `OidcClient`, call `set_login/set_ping/set_new_work_conn` |
| `frp-server/src/service.rs` | Create `OidcVerifier` in `AppState` |
| `frp-server/src/control.rs` | Verify login, store subject, verify ping/nwc |
