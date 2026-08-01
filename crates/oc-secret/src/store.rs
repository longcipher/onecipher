//! Filesystem-backed secret store with age-encrypted entries.
//!
//! Layout under the configured root directory:
//! ```text
//! <root>/
//! ├── secrets/           # one .age file per entry
//! │   ├── github.age
//! │   └── main-wallet.age
//! └── index.jsonl        # plaintext index (SecretIndexEntry per line)
//! ```
//!
//! The index is JSONL — one [`SecretIndexEntry`] per line — so it can be
//! searched and listed without touching the encrypted files. The encrypted
//! files hold the full [`SecretEntry`] (metadata + age ciphertext).
//!
//! # Permissions
//!
//! Per R42: secrets directory is 0700, entry files are 0600 (Unix only).

use std::path::{Path, PathBuf};

use oc_core::SecretIndexEntry;

use crate::entry::SecretEntry;

/// Auto-commit a change to the vault if the vault root is a git repository.
///
/// When the `git` feature is enabled, this delegates to
/// [`crate::git::auto_commit`]. When disabled, it is a no-op.
#[cfg(feature = "git")]
fn maybe_auto_commit(root: &Path, paths: &[&Path], message: &str) {
    let _ = crate::git::auto_commit(root, paths, message);
}

#[cfg(not(feature = "git"))]
fn maybe_auto_commit(_root: &Path, _paths: &[&Path], _message: &str) {
    // git feature disabled — no auto-commit.
}

/// Errors returned by [`SecretStore`] operations.
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("secret not found: '{0}'")]
    NotFound(String),
    #[error("secret already exists: '{0}'")]
    AlreadyExists(String),
    #[error("invalid name: {0}")]
    InvalidName(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("entry error: {0}")]
    Entry(#[from] crate::entry::SecretEntryError),
}

/// Configuration for a [`SecretStore`].
#[derive(Clone, Debug)]
pub struct StoreConfig {
    /// Root directory containing `secrets/` and `index.jsonl`.
    pub root: PathBuf,
}

impl StoreConfig {
    /// Create a new config with the given root directory.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// `<root>/secrets/`
    pub fn secrets_dir(&self) -> PathBuf {
        self.root.join("secrets")
    }

    /// `<root>/index.jsonl`
    pub fn index_path(&self) -> PathBuf {
        self.root.join("index.jsonl")
    }

    /// `<root>/secrets/<encoded-name>.age`
    ///
    /// The name is percent-encoded for the filesystem: `/` → `%2F`, `%` → `%25`.
    /// This allows hierarchical names like `github/personal` while keeping
    /// the filesystem flat and safe.
    pub fn entry_path(&self, name: &str) -> PathBuf {
        self.secrets_dir().join(format!("{}.age", name_to_filename(name)))
    }
}

/// A filesystem-backed store of age-encrypted secret entries.
///
/// All operations are synchronous (R56: no tokio / async runtime).
pub struct SecretStore {
    config: StoreConfig,
}

impl SecretStore {
    /// Open or initialize a secret store.
    ///
    /// Creates `root/`, `root/secrets/`, and `root/index.jsonl` if they
    /// don't already exist.
    pub fn open(config: StoreConfig) -> Result<Self, SecretStoreError> {
        std::fs::create_dir_all(&config.root)?;
        std::fs::create_dir_all(config.secrets_dir())?;
        set_dir_mode_0700(&config.root);
        set_dir_mode_0700(&config.secrets_dir());
        if !config.index_path().exists() {
            std::fs::write(config.index_path(), "")?;
        }
        set_file_mode_0600(&config.index_path());
        Ok(Self { config })
    }

    /// Return the store's configuration.
    pub const fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// List all entries by reading the plaintext index.
    pub fn list(&self) -> Result<Vec<SecretIndexEntry>, SecretStoreError> {
        let content = std::fs::read_to_string(self.config.index_path())?;
        let mut entries = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let entry: SecretIndexEntry = serde_json::from_str(line)?;
            entries.push(entry);
        }
        // Sort by name for deterministic output.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// Read a single encrypted entry by name.
    pub fn get(&self, name: &str) -> Result<SecretEntry, SecretStoreError> {
        validate_name(name)?;
        let path = self.config.entry_path(name);
        if !path.exists() {
            return Err(SecretStoreError::NotFound(name.into()));
        }
        let content = std::fs::read(&path)?;
        let entry: SecretEntry = serde_json::from_slice(&content)?;
        Ok(entry)
    }

    /// Write an encrypted entry to disk and update the index.
    ///
    /// If an entry with the same name already exists, it is overwritten.
    /// If the vault root is a git repository, the change is auto-committed.
    pub fn put(&self, entry: &SecretEntry) -> Result<(), SecretStoreError> {
        validate_name(&entry.name)?;
        let path = self.config.entry_path(&entry.name);
        let json = serde_json::to_vec_pretty(entry)?;
        std::fs::write(&path, json)?;
        set_file_mode_0600(&path);
        self.upsert_index(entry.to_index_entry())?;
        // Auto-commit if the vault is a git repository (silent no-op otherwise).
        let index_path = self.config.index_path();
        let paths = [path.as_path(), index_path.as_path()];
        maybe_auto_commit(&self.config.root, &paths, &format!("Add secret: {}", entry.name));
        Ok(())
    }

    /// Delete an entry (encrypted file + index record).
    /// If the vault root is a git repository, the deletion is auto-committed.
    pub fn delete(&self, name: &str) -> Result<(), SecretStoreError> {
        validate_name(name)?;
        let path = self.config.entry_path(name);
        if !path.exists() {
            return Err(SecretStoreError::NotFound(name.into()));
        }
        std::fs::remove_file(&path)?;
        self.remove_from_index(name)?;
        // Auto-commit the deletion.
        let index_path = self.config.index_path();
        let paths = [path.as_path(), index_path.as_path()];
        maybe_auto_commit(&self.config.root, &paths, &format!("Delete secret: {name}"));
        Ok(())
    }

    /// Rename an entry (file + index record).
    /// If the vault root is a git repository, the rename is auto-committed.
    pub fn rename(&self, old: &str, new: &str) -> Result<(), SecretStoreError> {
        validate_name(old)?;
        validate_name(new)?;
        if old == new {
            return Ok(());
        }
        let old_path = self.config.entry_path(old);
        let new_path = self.config.entry_path(new);
        if !old_path.exists() {
            return Err(SecretStoreError::NotFound(old.into()));
        }
        if new_path.exists() {
            return Err(SecretStoreError::AlreadyExists(new.into()));
        }
        // Load, rename in memory, write to new path, remove old file.
        let mut entry = self.get(old)?;
        entry.rename(new)?;
        let json = serde_json::to_vec_pretty(&entry)?;
        std::fs::write(&new_path, json)?;
        set_file_mode_0600(&new_path);
        std::fs::remove_file(&old_path)?;
        // Update index: remove old, add new.
        self.remove_from_index(old)?;
        self.upsert_index(entry.to_index_entry())?;
        // Auto-commit the rename.
        let index_path = self.config.index_path();
        let paths = [old_path.as_path(), new_path.as_path(), index_path.as_path()];
        maybe_auto_commit(&self.config.root, &paths, &format!("Rename secret: {old} to {new}"));
        Ok(())
    }

    /// Search the plaintext index by substring (case-insensitive).
    ///
    /// Matches against `name`, `metadata.url`, `metadata.username`,
    /// `metadata.issuer`, `metadata.account`, and `metadata.tags`.
    pub fn search(&self, query: &str) -> Result<Vec<SecretIndexEntry>, SecretStoreError> {
        let entries = self.list()?;
        if query.is_empty() {
            return Ok(entries);
        }
        let q = query.to_ascii_lowercase();
        Ok(entries
            .into_iter()
            .filter(|e| {
                e.name.to_ascii_lowercase().contains(&q) ||
                    e.metadata.url.as_ref().is_some_and(|s| s.to_ascii_lowercase().contains(&q)) ||
                    e.metadata
                        .username
                        .as_ref()
                        .is_some_and(|s| s.to_ascii_lowercase().contains(&q)) ||
                    e.metadata
                        .issuer
                        .as_ref()
                        .is_some_and(|s| s.to_ascii_lowercase().contains(&q)) ||
                    e.metadata
                        .account
                        .as_ref()
                        .is_some_and(|s| s.to_ascii_lowercase().contains(&q)) ||
                    e.metadata.tags.iter().any(|t| t.to_ascii_lowercase().contains(&q))
            })
            .collect())
    }

    // ── Index management (rewrite-on-write; fine for local vaults) ──

    fn upsert_index(&self, entry: SecretIndexEntry) -> Result<(), SecretStoreError> {
        let mut entries = self.list()?;
        entries.retain(|e| e.name != entry.name);
        entries.push(entry);
        self.write_index(&entries)
    }

    fn remove_from_index(&self, name: &str) -> Result<(), SecretStoreError> {
        let mut entries = self.list()?;
        entries.retain(|e| e.name != name);
        self.write_index(&entries)
    }

    fn write_index(&self, entries: &[SecretIndexEntry]) -> Result<(), SecretStoreError> {
        let mut content = String::new();
        for e in entries {
            let line = serde_json::to_string(e)?;
            content.push_str(&line);
            content.push('\n');
        }
        std::fs::write(self.config.index_path(), content)?;
        set_file_mode_0600(&self.config.index_path());
        Ok(())
    }
}

/// Reject names that could escape the secrets directory.
///
/// `/` is allowed — it is percent-encoded in filenames via [`name_to_filename`].
fn validate_name(name: &str) -> Result<(), SecretStoreError> {
    if name.trim().is_empty() {
        return Err(SecretStoreError::InvalidName("name must not be empty".into()));
    }
    if name.contains('\\') ||
        name.contains('\0') ||
        name == ".." ||
        name == "." ||
        name.starts_with('.')
    {
        return Err(SecretStoreError::InvalidName(format!(
            "name contains forbidden characters or sequences: '{name}'"
        )));
    }
    Ok(())
}

/// Percent-encode a secret name for filesystem storage.
///
/// Encodes `%` as `%25` first, then `/` as `%2F`. This allows hierarchical
/// names like `github/personal` while keeping the filesystem flat and safe.
fn name_to_filename(name: &str) -> String {
    name.replace('%', "%25").replace('/', "%2F")
}

#[cfg(unix)]
fn set_dir_mode_0700(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_path: &Path) {}

#[cfg(unix)]
fn set_file_mode_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_file_mode_0600(_path: &Path) {}

#[cfg(test)]
mod tests {
    use oc_core::{ItemType, SecretMetadata, SecretPayload};

    use super::*;
    use crate::age::AgeIdentity;

    fn make_store() -> (tempfile::TempDir, SecretStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(StoreConfig::new(dir.path().to_path_buf())).unwrap();
        (dir, store)
    }

    fn make_entry(name: &str, secret: &str) -> SecretEntry {
        let identity = AgeIdentity::generate();
        let recipient = identity.to_recipient_string();
        let payload = SecretPayload { secret: secret.into(), notes: None, extra: None };
        SecretEntry::new(
            name,
            ItemType::Password,
            &payload,
            SecretMetadata { url: Some("https://example.com".into()), ..Default::default() },
            &[recipient],
        )
        .unwrap()
    }

    #[test]
    fn open_creates_directories_and_index() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let store = SecretStore::open(StoreConfig::new(root)).unwrap();
        assert!(store.config.secrets_dir().exists());
        assert!(store.config.index_path().exists());
    }

    #[test]
    fn put_and_get_round_trip() {
        let (_dir, store) = make_store();
        let entry = make_entry("github", "hunter2");
        store.put(&entry).unwrap();

        let loaded = store.get("github").unwrap();
        assert_eq!(loaded.name, "github");
        assert_eq!(loaded.id, entry.id);
    }

    #[test]
    fn list_returns_index_entries() {
        let (_dir, store) = make_store();
        store.put(&make_entry("alpha", "a")).unwrap();
        store.put(&make_entry("beta", "b")).unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
        // Sorted by name.
        assert_eq!(list[0].name, "alpha");
        assert_eq!(list[1].name, "beta");
    }

    #[test]
    fn delete_removes_file_and_index() {
        let (_dir, store) = make_store();
        store.put(&make_entry("temp", "x")).unwrap();
        assert!(store.list().unwrap().iter().any(|e| e.name == "temp"));

        store.delete("temp").unwrap();
        assert!(!store.list().unwrap().iter().any(|e| e.name == "temp"));
        assert!(store.get("temp").is_err());
    }

    #[test]
    fn rename_moves_file_and_updates_index() {
        let (_dir, store) = make_store();
        store.put(&make_entry("old-name", "secret")).unwrap();
        store.rename("old-name", "new-name").unwrap();

        assert!(store.get("old-name").is_err());
        let loaded = store.get("new-name").unwrap();
        assert_eq!(loaded.name, "new-name");

        let list = store.list().unwrap();
        assert!(list.iter().any(|e| e.name == "new-name"));
        assert!(!list.iter().any(|e| e.name == "old-name"));
    }

    #[test]
    fn rename_to_existing_name_fails() {
        let (_dir, store) = make_store();
        store.put(&make_entry("a", "1")).unwrap();
        store.put(&make_entry("b", "2")).unwrap();
        let result = store.rename("a", "b");
        assert!(matches!(result, Err(SecretStoreError::AlreadyExists(_))));
    }

    #[test]
    fn get_nonexistent_fails() {
        let (_dir, store) = make_store();
        let result = store.get("nope");
        assert!(matches!(result, Err(SecretStoreError::NotFound(_))));
    }

    #[test]
    fn delete_nonexistent_fails() {
        let (_dir, store) = make_store();
        let result = store.delete("nope");
        assert!(matches!(result, Err(SecretStoreError::NotFound(_))));
    }

    #[test]
    fn search_matches_name() {
        let (_dir, store) = make_store();
        store.put(&make_entry("github-token", "x")).unwrap();
        store.put(&make_entry("gitlab-token", "y")).unwrap();

        let results = store.search("github").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "github-token");
    }

    #[test]
    fn search_matches_url() {
        let (_dir, store) = make_store();
        let identity = AgeIdentity::generate();
        let recipient = identity.to_recipient_string();
        let payload = SecretPayload { secret: "x".into(), notes: None, extra: None };
        let entry = SecretEntry::new(
            "my-entry",
            ItemType::Password,
            &payload,
            SecretMetadata {
                url: Some("https://unique-url.example.com".into()),
                ..Default::default()
            },
            &[recipient],
        )
        .unwrap();
        store.put(&entry).unwrap();

        let results = store.search("unique-url").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_empty_query_returns_all() {
        let (_dir, store) = make_store();
        store.put(&make_entry("a", "1")).unwrap();
        store.put(&make_entry("b", "2")).unwrap();
        let results = store.search("").unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn validate_name_rejects_dangerous_chars() {
        // '/' is now allowed (percent-encoded in filenames).
        assert!(validate_name("a/b").is_ok());
        assert!(validate_name("a\\b").is_err());
        assert!(validate_name("..").is_err());
        assert!(validate_name(".").is_err());
        assert!(validate_name(".hidden").is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name("  ").is_err());
    }

    #[test]
    fn validate_name_accepts_valid_names() {
        assert!(validate_name("github").is_ok());
        assert!(validate_name("github/personal").is_ok());
        assert!(validate_name("my-wallet").is_ok());
        assert!(validate_name("work_email").is_ok());
        assert!(validate_name("vault123").is_ok());
    }

    #[test]
    fn name_to_filename_encodes_slash_and_percent() {
        assert_eq!(name_to_filename("github"), "github");
        assert_eq!(name_to_filename("github/personal"), "github%2Fpersonal");
        assert_eq!(name_to_filename("100%done"), "100%25done");
        assert_eq!(name_to_filename("a/b%c"), "a%2Fb%25c");
    }

    #[test]
    fn put_overwrites_existing() {
        let (_dir, store) = make_store();
        store.put(&make_entry("dup", "first")).unwrap();
        store.put(&make_entry("dup", "second")).unwrap();
        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn file_permissions_are_strict() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = make_store();
        store.put(&make_entry("perm-test", "x")).unwrap();

        let entry_path = store.config.entry_path("perm-test");
        let mode = std::fs::metadata(&entry_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let dir_mode =
            std::fs::metadata(store.config.secrets_dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    #[cfg(feature = "git")]
    fn put_auto_commits_when_vault_is_git_repo() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(StoreConfig::new(dir.path().to_path_buf())).unwrap();

        // Initialize a git repo in the vault root.
        let repo = crate::git::init_repo(dir.path()).unwrap();
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        // Put a secret — should auto-commit.
        store.put(&make_entry("github", "hunter2")).unwrap();

        // Verify a commit was created.
        let entries = crate::git::history(&repo).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].message.contains("Add secret: github"));
    }

    #[test]
    #[cfg(feature = "git")]
    fn delete_auto_commits_when_vault_is_git_repo() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(StoreConfig::new(dir.path().to_path_buf())).unwrap();

        let repo = crate::git::init_repo(dir.path()).unwrap();
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        store.put(&make_entry("temp", "x")).unwrap();
        store.delete("temp").unwrap();

        let entries = crate::git::history(&repo).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].message.contains("Delete secret: temp"));
        assert!(entries[1].message.contains("Add secret: temp"));
    }

    #[test]
    #[cfg(feature = "git")]
    fn rename_auto_commits_when_vault_is_git_repo() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(StoreConfig::new(dir.path().to_path_buf())).unwrap();

        let repo = crate::git::init_repo(dir.path()).unwrap();
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        store.put(&make_entry("old-name", "secret")).unwrap();
        store.rename("old-name", "new-name").unwrap();

        let entries = crate::git::history(&repo).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].message.contains("Rename secret: old-name to new-name"));
    }

    #[test]
    fn operations_work_without_git_repo() {
        // Verify that put/delete/rename still work when there's no git repo.
        let (_dir, store) = make_store();
        store.put(&make_entry("a", "1")).unwrap();
        store.put(&make_entry("b", "2")).unwrap();
        store.delete("a").unwrap();
        store.rename("b", "c").unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "c");
    }
}
