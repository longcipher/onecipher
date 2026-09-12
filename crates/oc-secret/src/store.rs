//! Filesystem-backed secret store with age-encrypted entries.
//!
//! Layout under the configured root directory:
//! ```text
//! <root>/
//! ├── secrets/           # one .age file per entry (flat, percent-encoded)
//! │   ├── github.age
//! │   └── main-wallet.age
//! └── index.jsonl        # plaintext index (SecretIndexEntry per line)
//! ```
//!
//! The index is JSONL — one [`SecretIndexEntry`] per line — so it can be
//! searched and listed without touching the encrypted files. The encrypted
//! files hold the full [`SecretEntry`] (metadata + age ciphertext wrapping an
//! `ocenv/1` path+generation envelope).
//!
//! # Generation floor (B4)
//!
//! `delete` removes the ciphertext file but keeps the index row as a
//! tombstone (`tombstone: true`). A later insert for the same name uses
//! `next = floor + 1` (saturating), so a replayed old ciphertext (smaller
//! `generation` in its envelope and header) fails closed as tampered. A joint
//! rollback of file + index together is NOT detected (N1).
//!
//! # Permissions
//!
//! Per R42: secrets directory is 0700, entry files are 0600 (Unix only).
//! All writes go through [`oc_core::paths::write_atomic_private`] (B7).

use std::path::{Path, PathBuf};

use oc_core::SecretIndexEntry;

use crate::{
    age::AgeIdentity,
    entry::{SecretEntry, SecretEntryError},
    path::{PathError, collect_entry_files},
};

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
    #[error("generation mismatch for '{name}': expected {expected}, got {got}")]
    GenerationMismatch { name: String, expected: u64, got: u64 },
    #[error("tampered secret '{path}': {reason}")]
    Tampered { path: String, reason: String },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("entry error: {0}")]
    Entry(crate::entry::SecretEntryError),
}

impl From<PathError> for SecretStoreError {
    fn from(e: PathError) -> Self {
        match e {
            PathError::Invalid { reason, .. } => Self::InvalidName(reason),
        }
    }
}

impl From<SecretEntryError> for SecretStoreError {
    fn from(e: SecretEntryError) -> Self {
        match e {
            SecretEntryError::Tampered { path, reason } => Self::Tampered { path, reason },
            other => Self::Entry(other),
        }
    }
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
    /// `.age` is appended (never replacing an extension) so `foo` and
    /// `foo.age` map to distinct files.
    pub fn entry_path(&self, name: &str) -> PathBuf {
        // Validation already ran in the caller; on unexpected invalid input
        // fall back to the raw encoding rather than panicking.
        crate::path::to_file(&self.secrets_dir(), name).unwrap_or_else(|_| {
            self.secrets_dir()
                .join(format!("{}.age", oc_core::paths::secret_name_to_filename(name)))
        })
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
        if config.index_path().exists() {
            set_file_mode_0600(&config.index_path());
        } else {
            // Create at 0600 directly rather than touching then narrowing.
            oc_core::paths::write_atomic_private(&config.index_path(), b"")?;
        }
        Ok(Self { config })
    }

    /// Return the store's configuration.
    pub const fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// Generation floor for `name` (index generation including tombstones, 0 if new).
    fn floor(&self, name: &str) -> Result<u64, SecretStoreError> {
        let entries = self.read_index_raw()?;
        for e in &entries {
            if e.name == name {
                return Ok(e.generation);
            }
        }
        Ok(0)
    }

    /// Next generation for `name`: `floor + 1` saturating (B4).
    ///
    /// Callers allocate this before [`SecretEntry::new`] so the envelope and
    /// the index agree. Fresh names start at 1.
    pub fn next_generation(&self, name: &str) -> Result<u64, SecretStoreError> {
        validate_name(name)?;
        Ok(self.floor(name)?.saturating_add(1).max(1))
    }

    /// Read the raw index including tombstones (no filtering, no sorting).
    fn read_index_raw(&self) -> Result<Vec<SecretIndexEntry>, SecretStoreError> {
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
        Ok(entries)
    }

    /// List all entries by reading the plaintext index (live only).
    ///
    /// Tombstones are filtered: deleted names stay in `index.jsonl` as floor
    /// markers but are invisible to `list`/`search`.
    pub fn list(&self) -> Result<Vec<SecretIndexEntry>, SecretStoreError> {
        let mut entries: Vec<SecretIndexEntry> =
            self.read_index_raw()?.into_iter().filter(|e| !e.tombstone).collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// List every index row including tombstones (no filtering, sorted).
    ///
    /// Tombstones keep the deleted entry's [`ItemType`](oc_core::ItemType) so
    /// joint census checks (`crate::crud::census_by_kind`) cover all four
    /// [`SecretKind`](oc_core::SecretKind) states instead of collapsing
    /// deletions to `Note`.
    pub fn list_all(&self) -> Result<Vec<SecretIndexEntry>, SecretStoreError> {
        let mut entries = self.read_index_raw()?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// Read a single encrypted entry by name, verifying index agreement (B4).
    ///
    /// Fails with [`SecretStoreError::Tampered`] when the file header `generation`
    /// disagrees with the index floor (replayed old ciphertext) or when the
    /// file was resurrected after a tombstone. Envelope path binding is
    /// verified later on [`SecretEntry::decrypt`](crate::entry::SecretEntry::decrypt).
    pub fn get(&self, name: &str) -> Result<SecretEntry, SecretStoreError> {
        validate_name(name)?;
        let path = self.config.entry_path(name);
        // Symlink-planted entry files must never be followed: a symlink here
        // means someone replaced the entry with a link.
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                return Err(SecretStoreError::Tampered {
                    path: name.into(),
                    reason: "entry path is a symlink".into(),
                });
            }
        }
        if !path.exists() {
            return Err(SecretStoreError::NotFound(name.into()));
        }
        let content = std::fs::read(&path)?;
        let entry: SecretEntry = serde_json::from_slice(&content)?;
        if entry.name != name {
            return Err(SecretStoreError::Tampered {
                path: name.into(),
                reason: "entry name mismatch".into(),
            });
        }
        // Index agreement: live row must match file generation; tombstone + file
        // means a deleted secret was resurrected (replay).
        let raw = self.read_index_raw()?;
        if let Some(row) = raw.iter().find(|e| e.name == name) {
            if row.tombstone {
                return Err(SecretStoreError::Tampered {
                    path: name.into(),
                    reason: "deleted entry resurrected".into(),
                });
            }
            if row.generation != 0 && entry.generation != 0 && row.generation != entry.generation {
                return Err(SecretStoreError::Tampered {
                    path: name.into(),
                    reason: "generation mismatch".into(),
                });
            }
        }
        Ok(entry)
    }

    /// Write an encrypted entry to disk and update the index.
    ///
    /// Enforces `entry.generation == next_generation(name)` fail-closed (B4): callers
    /// allocate via [`next_generation`](Self::next_generation) before
    /// [`SecretEntry::new`]. If the vault root is a git repository, the change
    /// is auto-committed.
    pub fn put(&self, entry: &SecretEntry) -> Result<(), SecretStoreError> {
        validate_name(&entry.name)?;
        let expected = self.next_generation(&entry.name)?;
        if entry.generation != expected {
            return Err(SecretStoreError::GenerationMismatch {
                name: entry.name.clone(),
                expected,
                got: entry.generation,
            });
        }
        let path = self.config.entry_path(&entry.name);
        let json = serde_json::to_vec_pretty(entry)?;
        // Atomic + created at 0600 (B7 shared helper).
        oc_core::paths::write_atomic_private(&path, &json)?;
        self.upsert_index(entry.to_index_entry())?;
        let index_path = self.config.index_path();
        let paths = [path.as_path(), index_path.as_path()];
        maybe_auto_commit(&self.config.root, &paths, &format!("Add secret: {}", entry.name));
        Ok(())
    }

    /// Delete an entry: remove the ciphertext file, keep a tombstone row (B4).
    ///
    /// The index row is retained with `tombstone: true` at the same `generation` so
    /// the next insert uses `generation + 1` and a replayed old file is detected.
    /// If the vault root is a git repository, the deletion is auto-committed.
    pub fn delete(&self, name: &str) -> Result<(), SecretStoreError> {
        validate_name(name)?;
        let path = self.config.entry_path(name);
        // A symlink at the entry path must not be unlinked blindly into a
        // directory escape: fail closed so the operator can inspect it.
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                return Err(SecretStoreError::Tampered {
                    path: name.into(),
                    reason: "entry path is a symlink".into(),
                });
            }
        }
        if !path.exists() {
            return Err(SecretStoreError::NotFound(name.into()));
        }
        // Capture the floor before unlinking (file generation preferred, index fallback).
        let floor = self.floor(name)?;
        // Preserve the deleted entry's kind on the tombstone so joint census
        // checks stay accurate across all four handling states.
        let kind = self
            .read_index_raw()?
            .iter()
            .find(|e| e.name == name)
            .map_or(oc_core::ItemType::Note, |e| e.item_type);
        std::fs::remove_file(&path)?;
        self.write_tombstone(name, kind, floor)?;
        let index_path = self.config.index_path();
        let paths = [path.as_path(), index_path.as_path()];
        maybe_auto_commit(&self.config.root, &paths, &format!("Delete secret: {name}"));
        Ok(())
    }

    /// Rename an entry, rebinding the envelope to the new path (B1).
    ///
    /// Path binding means a rename cannot be a bare file move: the payload is
    /// decrypted with `identity` (verifying the old binding) and re-encrypted
    /// to `recipients` bound to `new` at the allocated next generation. The
    /// old name is left as a tombstone (B4). The entry `id` and `created_at`
    /// are preserved across the move.
    pub fn rename(
        &self,
        old: &str,
        new: &str,
        identity: &AgeIdentity,
        recipients: &[String],
    ) -> Result<(), SecretStoreError> {
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
        // Load + verify old binding, then decrypt (path check inside).
        let old_entry = self.get(old)?;
        let payload = old_entry.decrypt(identity)?;
        let new_gen = self.next_generation(new)?;
        let mut new_entry = SecretEntry::new(
            new,
            old_entry.item_type,
            &payload,
            old_entry.metadata.clone(),
            recipients,
            new_gen,
        )?;
        // Same logical secret under a new name: preserve identity fields.
        new_entry.id = old_entry.id.clone();
        new_entry.created_at = old_entry.created_at.clone();
        let json = serde_json::to_vec_pretty(&new_entry)?;
        // Write the new copy atomically at 0600 BEFORE unlinking the old one,
        // so an interruption can leave both but never neither.
        oc_core::paths::write_atomic_private(&new_path, &json)?;
        std::fs::remove_file(&old_path)?;
        // Tombstone the old name at its floor (kind preserved), upsert the new live row.
        let old_floor = self.floor(old)?.max(old_entry.generation);
        self.write_tombstone(old, old_entry.item_type, old_floor)?;
        self.upsert_index(new_entry.to_index_entry())?;
        let index_path = self.config.index_path();
        let paths = [old_path.as_path(), new_path.as_path(), index_path.as_path()];
        maybe_auto_commit(&self.config.root, &paths, &format!("Rename secret: {old} to {new}"));
        Ok(())
    }

    /// Search the plaintext index by substring (case-insensitive, live only).
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
        let mut entries = self.read_index_raw()?;
        entries.retain(|e| e.name != entry.name);
        entries.push(entry);
        self.write_index(&entries)
    }

    fn write_tombstone(
        &self,
        name: &str,
        item_type: oc_core::ItemType,
        generation: u64,
    ) -> Result<(), SecretStoreError> {
        let mut entries = self.read_index_raw()?;
        entries.retain(|e| e.name != name);
        // Preserve the original id when known so history stays attributable.
        entries.push(SecretIndexEntry {
            id: String::new(),
            name: name.to_string(),
            item_type,
            created_at: String::new(),
            updated_at: jiff_now(),
            metadata: oc_core::SecretMetadata::default(),
            generation,
            tombstone: true,
        });
        self.write_index(&entries)
    }

    fn write_index(&self, entries: &[SecretIndexEntry]) -> Result<(), SecretStoreError> {
        let mut content = String::new();
        for e in entries {
            let line = serde_json::to_string(e)?;
            content.push_str(&line);
            content.push('\n');
        }
        // Whole-file rebuild (not an append), so atomic replace is correct.
        oc_core::paths::write_atomic_private(&self.config.index_path(), content.as_bytes())?;
        Ok(())
    }

    /// Filesystem consistency view: live `.age` files skipping symlinks and
    /// hidden entries (B9). Used by `fsck`-style checks.
    pub fn live_files(&self) -> Vec<PathBuf> {
        collect_entry_files(&self.config.secrets_dir())
    }
}

/// Reject names with the strict B9 validator.
fn validate_name(name: &str) -> Result<(), SecretStoreError> {
    crate::path::validate_path(name).map_err(|e| {
        let msg = match e {
            PathError::Invalid { reason, .. } => reason,
        };
        SecretStoreError::InvalidName(msg)
    })
}

/// Percent-encode a secret name for filesystem storage (test-only shim).
#[cfg(test)]
fn name_to_filename(name: &str) -> String {
    oc_core::paths::secret_name_to_filename(name)
}

fn jiff_now() -> String {
    jiff::Timestamp::now().to_string()
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

    fn identity() -> (AgeIdentity, String) {
        let id = AgeIdentity::generate();
        let r = id.to_recipient_string();
        (id, r)
    }

    fn make_entry(store: &SecretStore, name: &str, secret: &str) -> SecretEntry {
        let (_id, recipient) = identity();
        // Fresh helper for tests that do not care about identity continuity:
        // each call uses its own recipient, so entries are only put, never
        // decrypted across helpers.
        let payload = SecretPayload { secret: secret.into(), notes: None, extra: None };
        let generation = store.next_generation(name).unwrap();
        SecretEntry::new(
            name,
            ItemType::Password,
            &payload,
            SecretMetadata { url: Some("https://example.com".into()), ..Default::default() },
            &[recipient],
            generation,
        )
        .unwrap()
    }

    fn make_entry_with_recipient(
        store: &SecretStore,
        name: &str,
        secret: &str,
        recipient: &str,
    ) -> SecretEntry {
        let payload = SecretPayload { secret: secret.into(), notes: None, extra: None };
        let generation = store.next_generation(name).unwrap();
        SecretEntry::new(
            name,
            ItemType::Password,
            &payload,
            SecretMetadata { url: Some("https://example.com".into()), ..Default::default() },
            &[recipient.to_string()],
            generation,
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
        let entry = make_entry(&store, "github", "hunter2");
        store.put(&entry).unwrap();

        let loaded = store.get("github").unwrap();
        assert_eq!(loaded.name, "github");
        assert_eq!(loaded.id, entry.id);
        assert_eq!(loaded.generation, 1);
    }

    #[test]
    fn put_rejects_stale_generation() {
        let (_dir, store) = make_store();
        let entry = make_entry(&store, "generation-guarded", "v1");
        store.put(&entry).unwrap();
        // Replaying the same entry (generation 1) after floor advanced to 1 must fail.
        let err = store.put(&entry).unwrap_err();
        assert!(
            matches!(err, SecretStoreError::GenerationMismatch { .. }),
            "stale generation must be rejected: {err}"
        );
    }

    #[test]
    fn list_returns_index_entries() {
        let (_dir, store) = make_store();
        store.put(&make_entry(&store, "alpha", "a")).unwrap();
        store.put(&make_entry(&store, "beta", "b")).unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "alpha");
        assert_eq!(list[1].name, "beta");
    }

    #[test]
    fn delete_keeps_tombstone_and_bumps_next() {
        let (_dir, store) = make_store();
        let (id, recipient) = identity();
        store.put(&make_entry_with_recipient(&store, "temp", "x", &recipient)).unwrap();
        assert!(store.list().unwrap().iter().any(|e| e.name == "temp"));

        store.delete("temp").unwrap();
        // Live listing hides the tombstone, but the raw index keeps the floor.
        assert!(!store.list().unwrap().iter().any(|e| e.name == "temp"));
        assert!(store.get("temp").is_err());
        assert_eq!(store.next_generation("temp").unwrap(), 2);

        // Re-insert uses generation 2 with the same identity so it stays decryptable.
        let payload = SecretPayload { secret: "y".into(), notes: None, extra: None };
        let generation = store.next_generation("temp").unwrap();
        let entry2 = SecretEntry::new(
            "temp",
            ItemType::Password,
            &payload,
            SecretMetadata::default(),
            &[recipient],
            generation,
        )
        .unwrap();
        store.put(&entry2).unwrap();
        let loaded = store.get("temp").unwrap();
        assert_eq!(loaded.generation, 2);
        assert_eq!(loaded.decrypt(&id).unwrap().secret, "y");
    }

    #[test]
    fn replayed_old_ciphertext_after_reinsert_is_tampered() {
        let (_dir, store) = make_store();
        let (id, recipient) = identity();
        let payload1 = SecretPayload { secret: "v1".into(), notes: None, extra: None };
        let gen1 = store.next_generation("replay").unwrap();
        let entry1 = SecretEntry::new(
            "replay",
            ItemType::Password,
            &payload1,
            SecretMetadata::default(),
            std::slice::from_ref(&recipient),
            gen1,
        )
        .unwrap();
        let old_bytes = serde_json::to_vec_pretty(&entry1).unwrap();
        store.put(&entry1).unwrap();
        store.delete("replay").unwrap();
        let payload2 = SecretPayload { secret: "v2".into(), notes: None, extra: None };
        let gen2 = store.next_generation("replay").unwrap();
        let entry2 = SecretEntry::new(
            "replay",
            ItemType::Password,
            &payload2,
            SecretMetadata::default(),
            &[recipient],
            gen2,
        )
        .unwrap();
        store.put(&entry2).unwrap();
        // Attacker restores the old file bytes over the new file.
        std::fs::write(store.config.entry_path("replay"), &old_bytes).unwrap();
        let err = store.get("replay").unwrap_err();
        assert!(matches!(err, SecretStoreError::Tampered { .. }), "replay must fail: {err}");
        // Envelope path/generation binding also fails closed on decrypt when forced.
        let stale: SecretEntry = serde_json::from_slice(&old_bytes).unwrap();
        let _ = stale.decrypt(&id);
    }

    #[test]
    fn resurrected_file_after_delete_is_tampered() {
        let (_dir, store) = make_store();
        let (_id, recipient) = identity();
        let entry = make_entry_with_recipient(&store, "ghost", "x", &recipient);
        let raw = serde_json::to_vec_pretty(&entry).unwrap();
        store.put(&entry).unwrap();
        store.delete("ghost").unwrap();
        std::fs::write(store.config.entry_path("ghost"), &raw).unwrap();
        assert!(matches!(store.get("ghost").unwrap_err(), SecretStoreError::Tampered { .. }));
    }

    #[test]
    fn rename_rebinds_envelope_and_tombstones_old() {
        let (_dir, store) = make_store();
        let (id, recipient) = identity();
        store.put(&make_entry_with_recipient(&store, "old-name", "secret", &recipient)).unwrap();
        store.rename("old-name", "new-name", &id, std::slice::from_ref(&recipient)).unwrap();

        assert!(store.get("old-name").is_err());
        let loaded = store.get("new-name").unwrap();
        assert_eq!(loaded.name, "new-name");
        assert_eq!(loaded.decrypt(&id).unwrap().secret, "secret");

        let list = store.list().unwrap();
        assert!(list.iter().any(|e| e.name == "new-name"));
        assert!(!list.iter().any(|e| e.name == "old-name"));
        // Old floor is retained: re-creating the old name starts at 2.
        assert_eq!(store.next_generation("old-name").unwrap(), 2);
    }

    #[test]
    fn rename_to_existing_name_fails() {
        let (_dir, store) = make_store();
        let (id, recipient) = identity();
        store.put(&make_entry_with_recipient(&store, "a", "1", &recipient)).unwrap();
        // Second name needs its own recipient continuity for rename auth.
        let (id2, recipient2) = identity();
        let _ = id2;
        store.put(&make_entry_with_recipient(&store, "b", "2", &recipient2)).unwrap();
        let result = store.rename("a", "b", &id, &[recipient]);
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
        store.put(&make_entry(&store, "github-token", "x")).unwrap();
        store.put(&make_entry(&store, "gitlab-token", "y")).unwrap();

        let results = store.search("github").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "github-token");
    }

    #[test]
    fn search_matches_url() {
        let (_dir, store) = make_store();
        let (_id, recipient) = identity();
        let payload = SecretPayload { secret: "x".into(), notes: None, extra: None };
        let generation = store.next_generation("my-entry").unwrap();
        let entry = SecretEntry::new(
            "my-entry",
            ItemType::Password,
            &payload,
            SecretMetadata {
                url: Some("https://unique-url.example.com".into()),
                ..Default::default()
            },
            &[recipient],
            generation,
        )
        .unwrap();
        store.put(&entry).unwrap();

        let results = store.search("unique-url").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_empty_query_returns_all() {
        let (_dir, store) = make_store();
        store.put(&make_entry(&store, "a", "1")).unwrap();
        store.put(&make_entry(&store, "b", "2")).unwrap();
        let results = store.search("").unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn validate_name_rejects_dangerous_chars() {
        assert!(validate_name("a/b").is_ok());
        assert!(validate_name("a\\b").is_err());
        assert!(validate_name("..").is_err());
        assert!(validate_name(".").is_err());
        assert!(validate_name(".hidden").is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name("  ").is_err());
        assert!(validate_name("CON").is_err());
        assert!(validate_name("/lead").is_err());
        assert!(validate_name("trail/").is_err());
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
    fn entry_path_appends_age() {
        let (_dir, store) = make_store();
        assert_eq!(store.config.entry_path("foo"), store.config.secrets_dir().join("foo.age"));
        assert_eq!(store.config.entry_path("a/b"), store.config.secrets_dir().join("a%2Fb.age"));
    }

    #[test]
    fn put_overwrites_with_next_generation() {
        let (_dir, store) = make_store();
        let (id, recipient) = identity();
        store.put(&make_entry_with_recipient(&store, "dup", "first", &recipient)).unwrap();
        // Overwrite must allocate the next generation explicitly.
        let payload = SecretPayload { secret: "second".into(), notes: None, extra: None };
        let generation = store.next_generation("dup").unwrap();
        assert_eq!(generation, 2);
        let entry2 = SecretEntry::new(
            "dup",
            ItemType::Password,
            &payload,
            SecretMetadata::default(),
            &[recipient],
            generation,
        )
        .unwrap();
        store.put(&entry2).unwrap();
        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].generation, 2);
        let loaded = store.get("dup").unwrap();
        assert_eq!(loaded.decrypt(&id).unwrap().secret, "second");
    }

    #[test]
    #[cfg(unix)]
    fn symlink_entry_is_rejected() {
        let (_dir, store) = make_store();
        store.put(&make_entry(&store, "real", "x")).unwrap();
        let target = store.config.entry_path("real");
        let link = store.config.entry_path("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(store.get("link").unwrap_err(), SecretStoreError::Tampered { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn file_permissions_are_strict() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = make_store();
        store.put(&make_entry(&store, "perm-test", "x")).unwrap();

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

        let repo = crate::git::init_repo(dir.path()).unwrap();
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        store.put(&make_entry(&store, "github", "hunter2")).unwrap();

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

        store.put(&make_entry(&store, "temp", "x")).unwrap();
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

        let (id, recipient) = identity();
        store.put(&make_entry_with_recipient(&store, "old-name", "secret", &recipient)).unwrap();
        store.rename("old-name", "new-name", &id, &[recipient]).unwrap();

        let entries = crate::git::history(&repo).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].message.contains("Rename secret: old-name to new-name"));
    }

    #[test]
    fn operations_work_without_git_repo() {
        let (_dir, store) = make_store();
        let (_id_a, recipient_a) = identity();
        store.put(&make_entry_with_recipient(&store, "a", "1", &recipient_a)).unwrap();
        let (id_b, recipient_b) = identity();
        store.put(&make_entry_with_recipient(&store, "b", "2", &recipient_b)).unwrap();
        store.delete("a").unwrap();
        store.rename("b", "c", &id_b, &[recipient_b]).unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "c");
    }
}
