use std::{
    fs,
    path::{Path, PathBuf},
};

use oc_core::ApiKeyFile;
use rand::RngExt;
use sha2::{Digest, Sha256};

use crate::error::OcWalletError;

/// Token prefix that signals agent mode in the credential parameter.
pub const TOKEN_PREFIX: &str = "oc_key_";

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Returns the keys directory, creating it with strict permissions if needed.
fn keys_dir(vault_path: Option<&Path>) -> Result<PathBuf, OcWalletError> {
    let base = oc_vault::resolve_vault_path(vault_path);
    let dir = base.join("keys");
    fs::create_dir_all(&dir)?;
    set_dir_permissions(&dir);
    Ok(dir)
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    if let Err(e) = fs::set_permissions(path, perms) {
        eprintln!("warning: failed to set permissions on {}: {e}", path.display());
    }
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) {}

#[cfg(unix)]
fn set_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    if let Err(e) = fs::set_permissions(path, perms) {
        eprintln!("warning: failed to set permissions on {}: {e}", path.display());
    }
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) {}

// ---------------------------------------------------------------------------
// Token generation and hashing
// ---------------------------------------------------------------------------

/// Generate a random API token: `oc_key_<64 hex chars>` (256 bits of entropy).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    format!("{TOKEN_PREFIX}{}", hex::encode(bytes))
}

/// SHA-256 hash of the raw token string, hex-encoded.
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

/// Save an API key file to `~/.onecipher/keys/<id>.json` with strict permissions.
pub fn save_api_key(key: &ApiKeyFile, vault_path: Option<&Path>) -> Result<(), OcWalletError> {
    let dir = keys_dir(vault_path)?;
    let path = dir.join(format!("{}.json", key.id));
    let json = serde_json::to_string_pretty(key)?;
    fs::write(&path, json)?;
    set_file_permissions(&path);
    Ok(())
}

/// Load an API key by its ID.
pub fn load_api_key(id: &str, vault_path: Option<&Path>) -> Result<ApiKeyFile, OcWalletError> {
    let dir = keys_dir(vault_path)?;
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(OcWalletError::Core(oc_core::OcError::ApiKeyNotFound));
    }
    let contents = fs::read_to_string(&path)?;
    let key: ApiKeyFile = serde_json::from_str(&contents)?;
    Ok(key)
}

/// Look up an API key by the SHA-256 hash of the token.
/// Scans all key files — O(n) in the number of keys.
pub fn load_api_key_by_token_hash(
    token_hash: &str,
    vault_path: Option<&Path>,
) -> Result<ApiKeyFile, OcWalletError> {
    let keys = list_api_keys(vault_path)?;
    keys.into_iter()
        .find(|k| k.token_hash == token_hash)
        .ok_or(OcWalletError::Core(oc_core::OcError::ApiKeyNotFound))
}

/// List all API keys, sorted by creation time (newest first).
pub fn list_api_keys(vault_path: Option<&Path>) -> Result<Vec<ApiKeyFile>, OcWalletError> {
    let dir = keys_dir(vault_path)?;
    let mut keys = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(keys),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<ApiKeyFile>(&contents) {
                Ok(k) => keys.push(k),
                Err(e) => eprintln!("warning: skipping {}: {e}", path.display()),
            },
            Err(e) => eprintln!("warning: skipping {}: {e}", path.display()),
        }
    }

    keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(keys)
}

/// Delete an API key by ID.
pub fn delete_api_key(id: &str, vault_path: Option<&Path>) -> Result<(), OcWalletError> {
    let dir = keys_dir(vault_path)?;
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(OcWalletError::Core(oc_core::OcError::ApiKeyNotFound));
    }
    fs::remove_file(&path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn test_key(id: &str, name: &str, token: &str) -> ApiKeyFile {
        ApiKeyFile {
            id: id.to_string(),
            name: name.to_string(),
            token_hash: hash_token(token),
            created_at: "2026-03-22T10:30:00Z".to_string(),
            wallet_ids: vec!["wallet-1".to_string()],
            policy_ids: vec!["policy-1".to_string()],
            expires_at: None,
            wallet_secrets: HashMap::new(),
            secret_permissions: oc_core::SecretPermissions::default(),
        }
    }

    #[test]
    fn generate_token_has_correct_format() {
        let token = generate_token();
        assert!(token.starts_with(TOKEN_PREFIX));
        // "oc_key_" (7 chars) + 64 hex chars = 71 total
        assert_eq!(token.len(), 71);
        // The hex part should be valid hex
        assert!(hex::decode(&token[TOKEN_PREFIX.len()..]).is_ok());
    }

    #[test]
    fn generate_token_is_unique() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn hash_token_is_deterministic() {
        let token = "oc_key_abc123";
        assert_eq!(hash_token(token), hash_token(token));
    }

    #[test]
    fn hash_token_differs_for_different_tokens() {
        assert_ne!(hash_token("oc_key_abc"), hash_token("oc_key_def"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let key = test_key("key-1", "claude-agent", "oc_key_test");

        save_api_key(&key, Some(&vault)).unwrap();
        let loaded = load_api_key("key-1", Some(&vault)).unwrap();

        assert_eq!(loaded.id, "key-1");
        assert_eq!(loaded.name, "claude-agent");
        assert_eq!(loaded.token_hash, key.token_hash);
    }

    #[test]
    fn lookup_by_token_hash() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let token = "oc_key_findme";
        let key = test_key("key-2", "finder", token);

        save_api_key(&key, Some(&vault)).unwrap();

        let found = load_api_key_by_token_hash(&hash_token(token), Some(&vault)).unwrap();
        assert_eq!(found.id, "key-2");
    }

    #[test]
    fn lookup_nonexistent_hash_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = load_api_key_by_token_hash("nonexistent-hash", Some(&vault));
        assert!(result.is_err());
    }

    #[test]
    fn list_returns_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let mut k1 = test_key("k1", "first", "t1");
        k1.created_at = "2026-03-20T10:00:00Z".to_string();

        let mut k2 = test_key("k2", "second", "t2");
        k2.created_at = "2026-03-22T10:00:00Z".to_string();

        save_api_key(&k1, Some(&vault)).unwrap();
        save_api_key(&k2, Some(&vault)).unwrap();

        let keys = list_api_keys(Some(&vault)).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].id, "k2"); // newest first
        assert_eq!(keys[1].id, "k1");
    }

    #[test]
    fn delete_removes_key() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let key = test_key("del-me", "delete", "token");

        save_api_key(&key, Some(&vault)).unwrap();
        assert_eq!(list_api_keys(Some(&vault)).unwrap().len(), 1);

        delete_api_key("del-me", Some(&vault)).unwrap();
        assert_eq!(list_api_keys(Some(&vault)).unwrap().len(), 0);
    }

    #[test]
    fn delete_nonexistent_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = delete_api_key("nope", Some(&vault));
        assert!(result.is_err());
    }

    #[test]
    fn list_empty_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let keys = list_api_keys(Some(&vault)).unwrap();
        assert!(keys.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn key_file_has_strict_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let key = test_key("perm-key", "perms", "token");

        save_api_key(&key, Some(&vault)).unwrap();

        let path = vault.join("keys/perm-key.json");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file should have 0600 permissions, got {:04o}", mode);

        let dir_mode = fs::metadata(vault.join("keys")).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "keys dir should have 0700 permissions, got {:04o}", dir_mode);
    }
}
