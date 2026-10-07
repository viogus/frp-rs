//! SSH host-key and authorized_keys file handling.
//!
//! Split out of `ssh_gateway.rs` as a pure text move; the parent re-imports
//! `load_or_generate_host_key`/`parse_authorized_keys` for `SshListener::new`,
//! and the sibling test modules exercise the line parsers directly.

use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Parse an authorized_keys file body into the gateway's allow-list.
///
/// Line grammar is OpenSSH's: `[options] keytype base64key [comment]` with
/// the keytype/base64 pair required. Options may hold quoted values with
/// embedded spaces or commas (`from="1.2.3.4, 5.6.7.8"`,
/// `command="echo hi"`), so locating the keytype needs a quote-aware
/// token scan: a token is a maximal run of characters outside double
/// quotes, and the FIRST adjacent `(t1, t2)` pair whose `t2` base64-
/// decodes to a key wins. Option tokens cannot produce a false pair —
/// they contain `=` or `,` (never true of a keytype) or are bare words
/// whose neighbor fails to decode. Each line is trimmed; blank lines and
/// `#` comments are skipped; a line with no parseable pair is dropped.
///
/// Certificate entries (`*-cert-v01@openssh.com` keytypes) are DROPPED
/// whole even when the blob decodes: frp-rs compares raw client public
/// keys against this list and has no CA trust store, so a cert line
/// cannot be honored with Go's certificate semantics — accepting the
/// embedded raw key without any CA validation would be worse than
/// dropping the line. Go `ssh.ParseAuthorizedKey` accepts cert entries
/// and validates them at auth time.
///
/// DELIBERATE DIVERGENCE from Go frp v0.71.0 (pkg/ssh/gateway.go
/// `loadAuthorizedKeysFromFile`): Go aborts on the FIRST line that fails
/// `ssh.ParseAuthorizedKey` (`return nil, err` → PublicKeyCallback answers
/// every pubkey attempt with "internal error" — fail-closed), so one
/// malformed line voids the whole file. frp-rs drops only the bad line and
/// keeps the rest. Also note Go re-reads the file on EVERY auth attempt,
/// while frp-rs caches it once at `SshListener::new` (load-once).
///
/// The leading `type` field is NOT cross-checked against the decoded key
/// (the blob itself carries the type); OpenSSH authorized_keys files with
/// a wrong-but-parseable type field are still accepted, mirroring the
/// russh decode used here — EXCEPT cert keytypes, which are dropped whole
/// (above).
///
/// Behavior-preserving extraction of the SshListener::new inline parse —
/// unit-tested (audit round-11 GAP5); options-prefix + cert-line handling
/// added in audit round-12 (A2/D6: the old parts[1]-as-base64 reader
/// silently dropped every options-prefixed line, and would have accepted
/// a cert anchor's embedded raw key with zero CA validation).
pub(super) fn parse_authorized_keys(content: &str) -> Vec<russh::keys::PublicKey> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(parse_authorized_key_line)
        .collect()
}

/// Parse one non-empty, non-comment authorized_keys line. `None` when the
/// line holds no supported key (bad line → dropped, per-line divergence;
/// cert-typed anchors → dropped whole; see `parse_authorized_keys`).
fn parse_authorized_key_line(line: &str) -> Option<russh::keys::PublicKey> {
    // Quote-aware tokenization with `\`-escape handling inside quotes, so
    // `from="a b,c",command="echo \"hi\""` tokens stay whole. Cheap: a
    // single pass, one small Vec, never more tokens than the line has
    // words — an authorized_keys line is operator-sized.
    let mut tokens: Vec<&str> = Vec::with_capacity(4);
    let mut start = None;
    let mut in_quote = false;
    let mut escaped = false;
    for (i, &b) in line.as_bytes().iter().enumerate() {
        if in_quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_quote = false;
            }
            continue;
        }
        match b {
            b'"' => in_quote = true,
            b if b.is_ascii_whitespace() => {
                if let Some(s) = start.take() {
                    tokens.push(&line[s..i]);
                }
            }
            _ => {
                if start.is_none() {
                    start = Some(i);
                }
            }
        }
    }
    if let Some(s) = start {
        tokens.push(&line[s..]);
    }
    for pair in tokens.windows(2) {
        // Certificate anchors are dropped whole, before any decode.
        if pair[0].contains("-cert-v01@") {
            return None;
        }
        // Option tokens contain '=' or ',' — a keytype never does.
        if pair[0].contains(['=', ',']) {
            continue;
        }
        // Bare option words (e.g. `restrict`, `no-port-forwarding`)
        // reach here; their neighbor is the keytype and fails to
        // decode, so the scan falls through to the real pair.
        if let Ok(key) = russh::keys::parse_public_key_base64(pair[1]) {
            return Some(key);
        }
    }
    None
}

/// Load or auto-generate the SSH host key.
///
/// Priority:
/// 1. `private_key_file` if set and file exists
/// 2. `auto_gen_path` if file exists
/// 3. Generate new Ed25519 key, write to `auto_gen_path`
pub(super) async fn load_or_generate_host_key(
    private_key_file: &str,
    auto_gen_path: &str,
) -> Result<russh::keys::PrivateKey, String> {
    // Try explicit key file first
    if !private_key_file.is_empty() && Path::new(private_key_file).exists() {
        return russh::keys::load_secret_key(private_key_file, None)
            .map_err(|e| format!("load key file {}: {}", private_key_file, e));
    }

    // Try auto-gen path
    if Path::new(auto_gen_path).exists() {
        return russh::keys::load_secret_key(auto_gen_path, None)
            .map_err(|e| format!("load auto-gen key {}: {}", auto_gen_path, e));
    }

    // Generate new Ed25519 key
    let mut rng = rand::rng();
    let key = russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)
        .map_err(|e| format!("generate key: {}", e))?;
    let pem = key
        .to_openssh(russh::keys::ssh_key::LineEnding::default())
        .map_err(|e| format!("serialize key: {}", e))?;

    // Write to auto-gen path (pem is Zeroizing<String>, derefs to String)
    if let Some(parent) = Path::new(auto_gen_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create dir for key: {}", e))?;
    }
    std::fs::write(auto_gen_path, pem.as_bytes())
        .map_err(|e| format!("write auto-gen key {}: {}", auto_gen_path, e))?;

    // Restrict permissions: private key must be 0600 (owner read/write only).
    // Default umask typically creates 0644, which is world-readable.
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(auto_gen_path)
            .map_err(|e| format!("stat key file: {}", e))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(auto_gen_path, perms)
            .map_err(|e| format!("set key permissions: {}", e))?;
    }

    Ok(key)
}
