use super::*;
use tempfile::TempDir;

#[tokio::test]
async fn test_auto_gen_key_creates_file() {
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("test_key");
    let key_path_str = key_path.to_str().unwrap();

    let key = load_or_generate_host_key("", key_path_str).await.unwrap();
    assert!(key_path.exists());

    let data = std::fs::read_to_string(&key_path).unwrap();
    assert!(data.contains("BEGIN OPENSSH PRIVATE KEY"));

    // Verify it's an Ed25519 key
    assert!(matches!(key.algorithm(), russh::keys::Algorithm::Ed25519));
}

#[tokio::test]
async fn test_auto_gen_key_reuses_existing() {
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("test_key");
    let key_path_str = key_path.to_str().unwrap();

    // First call generates
    let key1 = load_or_generate_host_key("", key_path_str).await.unwrap();

    // Second call reuses
    let mtime_before = std::fs::metadata(&key_path).unwrap().modified().unwrap();
    let key2 = load_or_generate_host_key("", key_path_str).await.unwrap();
    let mtime_after = std::fs::metadata(&key_path).unwrap().modified().unwrap();

    // File not overwritten
    assert_eq!(mtime_before, mtime_after);
    // Same key type
    assert!(matches!(key2.algorithm(), russh::keys::Algorithm::Ed25519));
    // Same key: fingerprints should match
    use russh::keys::ssh_key::HashAlg;
    let fp1 = key1.public_key().fingerprint(HashAlg::Sha256);
    let fp2 = key2.public_key().fingerprint(HashAlg::Sha256);
    assert_eq!(fp1.to_string(), fp2.to_string());
}

#[tokio::test]
async fn test_explicit_key_file_takes_priority() {
    let dir = TempDir::new().unwrap();

    // Create auto-gen key
    let auto_path = dir.path().join("auto_key");
    let auto = load_or_generate_host_key("", auto_path.to_str().unwrap())
        .await
        .unwrap();

    // Create explicit key
    let explicit_path = dir.path().join("explicit_key");
    let mut rng = rand::rng();
    let explicit =
        russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap();
    let pem = explicit
        .to_openssh(russh::keys::ssh_key::LineEnding::default())
        .unwrap();
    std::fs::write(&explicit_path, pem.as_bytes()).unwrap();

    // Load with explicit path set -- should use explicit, not auto
    let loaded =
        load_or_generate_host_key(explicit_path.to_str().unwrap(), auto_path.to_str().unwrap())
            .await
            .unwrap();

    // Both are Ed25519 -- verify they're different keys
    use russh::keys::ssh_key::HashAlg;
    let loaded_fp = loaded.public_key().fingerprint(HashAlg::Sha256);
    let auto_fp = auto.public_key().fingerprint(HashAlg::Sha256);
    assert_ne!(loaded_fp.to_string(), auto_fp.to_string());
}
