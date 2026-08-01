//! Filesystem vault for encrypted wallet files (Keystore v3 derivatives).
//!
//! Fully designed and implemented in accordance with the Open Wallet Standard with the following
//! renames:
//! - `ows_core` → `oc_core`
//! - `OwsLibError` → `OcVaultError`
//! - `ows_version` → `oc_version` (handled in `oc-core::wallet_file`)
//!
//! Behavioral contract (R42):
//! - Vault file mode is 0600, parent dir 0700, owner = daemon user (Unix only).
//! - `save_encrypted_wallet` writes `<vault>/wallets/<id>.json` with 0600 perms.
//! - `wallets_dir` creates `<vault>/wallets/` with 0700 perms.
//!
//! Additionally exposes a [`Vault`] wrapper that loads a single wallet file
//! and decrypts its `crypto` envelope via `oc_signer::decrypt`.

use std::{
    fs,
    path::{Path, PathBuf},
};

use oc_core::{Config, EncryptedWallet};
use oc_crypto::HardenedBytes;
use oc_signer::{CryptoEnvelope, decrypt};
use tracing::warn;

use crate::error::OcVaultError;

/// Set directory permissions to 0o700 (owner-only).
#[cfg(unix)]
fn set_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    if let Err(e) = fs::set_permissions(path, perms) {
        warn!(target: "oc-vault", "failed to set permissions on {}: {e}", path.display());
    }
}

/// Set file permissions to 0o600 (owner read/write only).
#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<(), OcVaultError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

/// Check that a directory has permissions of exactly 0o700 (owner-only).
///
/// Returns `Err(InsecurePermissions)` if the mode is not 0o700, or
/// `Err(Io)` if the directory metadata cannot be read.
#[cfg(unix)]
pub fn check_vault_permissions(path: &Path) -> Result<(), OcVaultError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(OcVaultError::InsecurePermissions(mode));
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) {}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<(), OcVaultError> {
    Ok(())
}

#[cfg(not(unix))]
pub fn check_vault_permissions(_path: &Path) -> Result<(), OcVaultError> {
    Ok(())
}

/// Resolve the vault path: use explicit path if provided, otherwise default (~/.onecipher).
pub fn resolve_vault_path(vault_path: Option<&Path>) -> PathBuf {
    match vault_path {
        Some(p) => p.to_path_buf(),
        None => Config::default().vault_path,
    }
}

/// Returns the wallets directory, creating it with strict permissions if necessary.
pub fn wallets_dir(vault_path: Option<&Path>) -> Result<PathBuf, OcVaultError> {
    let vault_dir = resolve_vault_path(vault_path);
    let dir = vault_dir.join("wallets");
    fs::create_dir_all(&dir)?;
    set_dir_permissions(&vault_dir);
    set_dir_permissions(&dir);
    Ok(dir)
}

/// Save an encrypted wallet file with strict permissions.
///
/// Uses an atomic write-to-tmp + rename pattern to prevent partial writes
/// and TOCTOU permission races. The tmp file gets 0600 permissions before
/// the rename, so the final file is never readable by others even briefly.
pub fn save_encrypted_wallet(
    wallet: &EncryptedWallet,
    vault_path: Option<&Path>,
) -> Result<(), OcVaultError> {
    // Validate wallet ID to prevent path traversal
    if wallet.id.contains('/') || wallet.id.contains('\\') || wallet.id.contains("..") {
        return Err(OcVaultError::InvalidInput(format!(
            "wallet ID contains path separator or '..': {}",
            wallet.id
        )));
    }
    let dir = wallets_dir(vault_path)?;
    let path = dir.join(format!("{}.json", wallet.id));
    let tmp_path = dir.join(format!("{}.json.tmp", wallet.id));
    let json = serde_json::to_string_pretty(wallet)?;
    // Atomic write: write to tmp file, set permissions, then rename
    fs::write(&tmp_path, &json)?;
    set_file_permissions(&tmp_path)?;
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Load all encrypted wallets from the vault.
/// Checks directory permissions and returns `InsecurePermissions` if the
/// wallets directory is not `0o700`.
/// Returns wallets sorted by created_at descending (newest first).
pub fn list_encrypted_wallets(
    vault_path: Option<&Path>,
) -> Result<Vec<EncryptedWallet>, OcVaultError> {
    let dir = wallets_dir(vault_path)?;
    check_vault_permissions(&dir)?;

    let mut wallets = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(wallets),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<EncryptedWallet>(&contents) {
                Ok(w) => wallets.push(w),
                Err(e) => {
                    warn!(target: "oc-vault", "skipping {}: {e}", path.display());
                }
            },
            Err(e) => {
                warn!(target: "oc-vault", "skipping {}: {e}", path.display());
            }
        }
    }

    wallets.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(wallets)
}

/// Look up a wallet by exact ID first, then by name (case-sensitive).
/// Returns an error if no wallet matches or if the name is ambiguous.
pub fn load_wallet_by_name_or_id(
    name_or_id: &str,
    vault_path: Option<&Path>,
) -> Result<EncryptedWallet, OcVaultError> {
    let wallets = list_encrypted_wallets(vault_path)?;

    // Try exact ID match first
    if let Some(w) = wallets.iter().find(|w| w.id == name_or_id) {
        return Ok(w.clone());
    }

    // Try name match (case-sensitive)
    let matches: Vec<&EncryptedWallet> = wallets.iter().filter(|w| w.name == name_or_id).collect();
    match matches.len() {
        0 => Err(OcVaultError::WalletNotFound(name_or_id.to_string())),
        1 => Ok(matches[0].clone()),
        n => Err(OcVaultError::AmbiguousWallet { name: name_or_id.to_string(), count: n }),
    }
}

/// Delete a wallet file from the vault by ID.
pub fn delete_wallet_file(id: &str, vault_path: Option<&Path>) -> Result<(), OcVaultError> {
    // Validate wallet ID to prevent path traversal
    if id.contains('/') || id.contains('\\') || id.contains("..") {
        return Err(OcVaultError::InvalidInput(format!(
            "wallet ID contains path separator or '..': {id}"
        )));
    }
    let dir = wallets_dir(vault_path)?;
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(OcVaultError::WalletNotFound(id.to_string()));
    }
    fs::remove_file(&path)?;
    Ok(())
}

/// Check whether a wallet with the given name already exists in the vault.
pub fn wallet_name_exists(name: &str, vault_path: Option<&Path>) -> Result<bool, OcVaultError> {
    let wallets = list_encrypted_wallets(vault_path)?;
    Ok(wallets.iter().any(|w| w.name == name))
}

/// A loaded wallet file with its `crypto` envelope ready for decryption.
///
/// This is the `Vault` wrapper required by the T6 spec:
/// `Vault::load(path)` reads + parses the JSON; `Vault::decrypt(key)`
/// interprets the `HardenedBytes` as a UTF-8 passphrase and runs the
/// standard `oc_signer::decrypt` (argon2id + AES-256-GCM-SIV by default,
/// or HKDF if the envelope says so).
pub struct Vault {
    wallet: EncryptedWallet,
}

impl Vault {
    /// Load and parse a wallet JSON file from disk.
    pub fn load(path: &Path) -> Result<Self, OcVaultError> {
        let json = fs::read_to_string(path)?;
        let wallet: EncryptedWallet = serde_json::from_str(&json)?;
        Ok(Self { wallet })
    }

    /// Decrypt the wallet's `crypto` envelope using `key` as the passphrase.
    ///
    /// `key` must contain valid UTF-8 (it is fed to `oc_signer::decrypt`
    /// which takes `&str`). Non-UTF-8 bytes are rejected with
    /// [`OcVaultError::InvalidInput`].
    pub fn decrypt(&self, key: &HardenedBytes) -> Result<HardenedBytes, OcVaultError> {
        let envelope: CryptoEnvelope = serde_json::from_value(self.wallet.crypto.clone())
            .map_err(|e| OcVaultError::InvalidFormat(e.to_string()))?;
        let passphrase = std::str::from_utf8(key.expose())
            .map_err(|_| OcVaultError::InvalidInput("key is not valid UTF-8".into()))?;
        let plaintext = decrypt(&envelope, passphrase.as_bytes())
            .map_err(|e| OcVaultError::Crypto(e.to_string()))?;
        Ok(plaintext)
    }

    /// Borrow the underlying wallet record.
    pub const fn wallet(&self) -> &EncryptedWallet {
        &self.wallet
    }

    /// Consume into the underlying wallet record.
    pub fn into_wallet(self) -> EncryptedWallet {
        self.wallet
    }
}

/// Generic vault path helper for any age-encrypted secret store.
///
/// This is a thin path-resolver over a vault root directory. It does **not**
/// perform any I/O or encryption itself — it merely centralizes the layout
/// conventions shared by the wallet vault (`<root>/wallets/`) and the unified
/// secret store (`<root>/secrets/`, `<root>/keys/`, `<root>/index.jsonl`).
///
/// `Vault` (above) is wallet-specific: it loads and decrypts a single
/// `<root>/wallets/<id>.json` file. `SecretVault` is the generic counterpart
/// for non-wallet secrets and for code that needs to reason about the vault
/// layout without pulling in `oc_secret` (which would create a dependency
/// cycle, since `oc_secret` already depends on `oc_vault`).
pub struct SecretVault {
    root: PathBuf,
}

impl std::fmt::Debug for SecretVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretVault").field("root", &self.root).finish()
    }
}

impl SecretVault {
    /// Create a new `SecretVault` rooted at `root`.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Create a `SecretVault` from an optional explicit path, falling back to
    /// the default vault path (`~/.onecipher`) when `vault_path` is `None`.
    pub fn with_vault_path(vault_path: Option<&Path>) -> Self {
        Self::new(resolve_vault_path(vault_path))
    }

    /// The vault root directory.
    pub const fn root(&self) -> &PathBuf {
        &self.root
    }

    /// `<root>/wallets/` — legacy keystore v3 wallet files.
    pub fn wallets_dir(&self) -> PathBuf {
        self.root.join("wallets")
    }

    /// `<root>/secrets/` — age-encrypted secret entries.
    pub fn secrets_dir(&self) -> PathBuf {
        self.root.join("secrets")
    }

    /// `<root>/keys/` — API key files for agent access.
    pub fn keys_dir(&self) -> PathBuf {
        self.root.join("keys")
    }

    /// `<root>/index.jsonl` — plaintext secret index.
    pub fn index_path(&self) -> PathBuf {
        self.root.join("index.jsonl")
    }
}

#[cfg(test)]
mod tests {
    use oc_core::{KeyType, WalletAccount};

    use super::*;

    #[test]
    fn test_wallets_dir_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let result = wallets_dir(Some(&vault)).unwrap();
        assert!(result.exists());
        assert_eq!(result, vault.join("wallets"));
    }

    #[test]
    fn test_save_and_list_wallets() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "test-id".to_string(),
            "test-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();
        let wallets = list_encrypted_wallets(Some(&vault)).unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].id, "test-id");
    }

    #[test]
    fn test_load_by_name_or_id() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "uuid-123".to_string(),
            "my-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        // Find by ID
        let found = load_wallet_by_name_or_id("uuid-123", Some(&vault)).unwrap();
        assert_eq!(found.name, "my-wallet");

        // Find by name
        let found = load_wallet_by_name_or_id("my-wallet", Some(&vault)).unwrap();
        assert_eq!(found.id, "uuid-123");

        // Not found
        let err = load_wallet_by_name_or_id("nonexistent", Some(&vault));
        assert!(err.is_err());
    }

    #[test]
    fn test_delete_wallet_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "del-id".to_string(),
            "del-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();
        assert_eq!(list_encrypted_wallets(Some(&vault)).unwrap().len(), 1);

        delete_wallet_file("del-id", Some(&vault)).unwrap();
        assert_eq!(list_encrypted_wallets(Some(&vault)).unwrap().len(), 0);
    }

    #[test]
    fn test_wallet_name_exists() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "id-1".to_string(),
            "existing-name".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();
        assert!(wallet_name_exists("existing-name", Some(&vault)).unwrap());
        assert!(!wallet_name_exists("other-name", Some(&vault)).unwrap());
    }

    // === Characterization tests: lock down current behavior before refactoring ===

    #[test]
    fn char_save_and_load_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "char-id-123".to_string(),
            "char-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        let loaded = load_wallet_by_name_or_id("char-id-123", Some(&vault)).unwrap();
        assert_eq!(loaded.id, wallet.id);
        assert_eq!(loaded.name, wallet.name);
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.accounts[0].address, "0xabc");
        assert_eq!(loaded.key_type, KeyType::Mnemonic);
    }

    #[test]
    fn char_save_and_load_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "char-uuid-456".to_string(),
            "my-char-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        let loaded = load_wallet_by_name_or_id("my-char-wallet", Some(&vault)).unwrap();
        assert_eq!(loaded.id, "char-uuid-456");
    }

    #[test]
    fn char_path_traversal_in_save_rejected() {
        // Wallet IDs with path traversal components must be rejected
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "../../../etc/passwd".to_string(),
            "evil-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        let result = save_encrypted_wallet(&wallet, Some(&vault));
        assert!(result.is_err(), "path traversal wallet ID must be rejected");

        // No tmp files should be left behind
        let wallets_dir_path = vault.join("wallets");
        assert!(
            !wallets_dir_path.join("../../../etc/passwd.json.tmp").exists(),
            "tmp file must not be created for path traversal IDs"
        );
    }

    #[test]
    fn char_path_traversal_in_delete_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        // Create a legitimate wallet first
        let wallet = EncryptedWallet::new(
            "legit-id".to_string(),
            "legit".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        // Attempt to delete with path traversal — must be rejected with InvalidInput
        let result = delete_wallet_file("../../../etc/passwd", Some(&vault));
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), OcVaultError::InvalidInput(_)),
            "path traversal in delete must return InvalidInput"
        );

        // Original wallet should still exist
        assert_eq!(list_encrypted_wallets(Some(&vault)).unwrap().len(), 1);
    }

    #[test]
    fn char_list_returns_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let w1 = EncryptedWallet::new(
            "w1-id".to_string(),
            "wallet-1".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&w1, Some(&vault)).unwrap();

        // Sleep a tiny bit to ensure different created_at timestamps
        std::thread::sleep(std::time::Duration::from_millis(10));

        let w2 = EncryptedWallet::new(
            "w2-id".to_string(),
            "wallet-2".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&w2, Some(&vault)).unwrap();

        let wallets = list_encrypted_wallets(Some(&vault)).unwrap();
        assert_eq!(wallets.len(), 2);
        // Newest first
        assert_eq!(wallets[0].id, "w2-id");
        assert_eq!(wallets[1].id, "w1-id");
    }

    #[test]
    fn char_duplicate_wallet_name_detected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let w1 = EncryptedWallet::new(
            "id-a".to_string(),
            "same-name".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&w1, Some(&vault)).unwrap();

        assert!(wallet_name_exists("same-name", Some(&vault)).unwrap());
    }

    #[test]
    fn char_wallet_not_found_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = load_wallet_by_name_or_id("nonexistent", Some(&vault));
        assert!(result.is_err());
        match result.unwrap_err() {
            OcVaultError::WalletNotFound(name) => assert_eq!(name, "nonexistent"),
            other => panic!("expected WalletNotFound, got: {other}"),
        }
    }

    #[test]
    fn char_delete_nonexistent_wallet_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = delete_wallet_file("no-such-id", Some(&vault));
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn char_wallet_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "perm-id".to_string(),
            "perm-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        // Check file permissions are 0o600
        let file_path = vault.join("wallets/perm-id.json");
        let meta = std::fs::metadata(&file_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "wallet file should have 0600 permissions, got {:04o}", mode);

        // Check directory permissions are 0o700
        let wallets_dir_path = vault.join("wallets");
        let dir_meta = std::fs::metadata(&wallets_dir_path).unwrap();
        let dir_mode = dir_meta.permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "wallets directory should have 0700 permissions, got {:04o}",
            dir_mode
        );
    }

    // === Vault wrapper tests ===

    #[test]
    fn vault_load_and_decrypt_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let vault_dir = dir.path().to_path_buf();

        // Use oc_signer::encrypt to build a real crypto envelope
        let passphrase = "correct horse battery staple";
        let plaintext = b"super secret key material";

        let envelope = oc_signer::encrypt(plaintext, passphrase.as_bytes()).unwrap();
        let wallet = EncryptedWallet::new(
            "vault-rt-id".to_string(),
            "vault-rt".to_string(),
            vec![],
            serde_json::to_value(&envelope).unwrap(),
            KeyType::Mnemonic,
        );

        let wallet_path = vault_dir.join("wallet.json");
        std::fs::write(&wallet_path, serde_json::to_string_pretty(&wallet).unwrap()).unwrap();

        let loaded = Vault::load(&wallet_path).unwrap();
        assert_eq!(loaded.wallet().id, "vault-rt-id");

        // HardenedBytes holding the passphrase UTF-8 bytes.
        let key = HardenedBytes::from_slice(passphrase.as_bytes()).unwrap();
        let decrypted = loaded.decrypt(&key).unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn vault_decrypt_wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault_dir = dir.path().to_path_buf();

        let envelope = oc_signer::encrypt(b"secret", b"correct").unwrap();
        let wallet = EncryptedWallet::new(
            "wp-id".to_string(),
            "wp".to_string(),
            vec![],
            serde_json::to_value(&envelope).unwrap(),
            KeyType::Mnemonic,
        );

        let wallet_path = vault_dir.join("wp.json");
        std::fs::write(&wallet_path, serde_json::to_string_pretty(&wallet).unwrap()).unwrap();

        let loaded = Vault::load(&wallet_path).unwrap();
        let wrong_key = HardenedBytes::from_slice(b"wrong-passphrase").unwrap();
        let result = loaded.decrypt(&wrong_key);
        assert!(matches!(result, Err(OcVaultError::Crypto(_))));
    }

    #[test]
    fn vault_decrypt_non_utf8_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault_dir = dir.path().to_path_buf();

        let envelope = oc_signer::encrypt(b"x", b"pass").unwrap();
        let wallet = EncryptedWallet::new(
            "nu-id".to_string(),
            "nu".to_string(),
            vec![],
            serde_json::to_value(&envelope).unwrap(),
            KeyType::Mnemonic,
        );

        let wallet_path = vault_dir.join("nu.json");
        std::fs::write(&wallet_path, serde_json::to_string_pretty(&wallet).unwrap()).unwrap();

        let loaded = Vault::load(&wallet_path).unwrap();
        // 0xFF is not valid UTF-8 in isolation
        let bad_key = HardenedBytes::from_slice(&[0xFF, 0xFE, 0xFD]).unwrap();
        let result = loaded.decrypt(&bad_key);
        assert!(matches!(result, Err(OcVaultError::InvalidInput(_))));
    }

    // === SecretVault path helper tests ===

    #[test]
    fn secret_vault_paths() {
        let v = SecretVault::new(PathBuf::from("/tmp/oc-test"));
        assert_eq!(v.root(), &PathBuf::from("/tmp/oc-test"));
        assert_eq!(v.wallets_dir(), PathBuf::from("/tmp/oc-test/wallets"));
        assert_eq!(v.secrets_dir(), PathBuf::from("/tmp/oc-test/secrets"));
        assert_eq!(v.keys_dir(), PathBuf::from("/tmp/oc-test/keys"));
        assert_eq!(v.index_path(), PathBuf::from("/tmp/oc-test/index.jsonl"));
    }

    #[test]
    fn secret_vault_with_explicit_path() {
        let dir = tempfile::tempdir().unwrap();
        let v = SecretVault::with_vault_path(Some(dir.path()));
        assert_eq!(v.root(), dir.path());
        assert!(v.wallets_dir().starts_with(dir.path()));
    }
}
