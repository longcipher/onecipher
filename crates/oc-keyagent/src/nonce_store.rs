//! Single-use Sign-In with X (CAIP-122) replay protection.
//!
//! The `siwx` message model treats the nonce store as application-owned
//! (out of scope for the message crate). The Key-Agent owns it here: every
//! `SignSiwx` request consumes the SHA-256 hash of the exact message bytes,
//! so a captured login message cannot be signed a second time.
//!
//! Stored as a JSON map `hash_hex -> expires_at_unix` at
//! `~/.onecipher/siwx_nonces.json` (mode 0600, parent dir 0700) — same layout
//! conventions as [`crate::session_keys::SessionKeyStore`]. Expired entries
//! are garbage-collected on every load so the file stays bounded.
//!
//! Per R56: synchronous std only, NO tokio / async.

use std::{collections::HashMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};

/// Default time-to-live for a consumed message hash without an explicit
/// `expiration_time` (24 hours).
pub const DEFAULT_SIWZ_TTL_SECS: u64 = 86_400;

/// Hard cap on tracked hashes. Expired entries are evicted first; when the
/// map is still full the oldest-expiring entry is replaced (fail-open on
/// capacity would be a replay hole, fail-closed would brick logins —
/// evicting the *oldest* entry bounds the replay window instead of denying
/// fresh logins).
pub const MAX_NONCE_ENTRIES: usize = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum NonceStoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HOME not set")]
    HomeNotSet,
    #[error(
        "siwx nonce store at {path} is corrupt: {detail} — restore it from a backup or remove \
         the file"
    )]
    Corrupt { path: String, detail: String },
    /// The exact message bytes were already consumed (replay attempt).
    #[error("siwx message already consumed (replay detected)")]
    Replay,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// File-backed single-use registry of consumed Sign-In message hashes.
pub struct NonceStore {
    path: PathBuf,
}

impl NonceStore {
    /// Open the default store at `~/.onecipher/siwx_nonces.json`.
    pub fn open_default() -> Result<Self, NonceStoreError> {
        let path = oc_core::paths::state_path("siwx_nonces.json")
            .map_err(|_| NonceStoreError::HomeNotSet)?;
        Ok(Self { path })
    }

    /// Open a store at a specific path (tests / embedders).
    pub fn open(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load the hash map, dropping expired entries. Missing file = empty map;
    /// a parse failure is an explicit [`NonceStoreError::Corrupt`]
    /// (fail-closed).
    fn load(&self) -> Result<HashMap<String, u64>, NonceStoreError> {
        let now = now_unix();
        let mut map: HashMap<String, u64> = match fs::read_to_string(&self.path) {
            Ok(contents) if contents.trim().is_empty() => HashMap::new(),
            Ok(contents) => {
                serde_json::from_str(&contents).map_err(|e| NonceStoreError::Corrupt {
                    path: self.path.display().to_string(),
                    detail: e.to_string(),
                })?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e.into()),
        };
        map.retain(|_, exp| *exp > now);
        Ok(map)
    }

    /// Persist the map atomically with mode 0600.
    fn save(&self, map: &HashMap<String, u64>) -> Result<(), NonceStoreError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let json = serde_json::to_string(map)?;
        oc_core::paths::write_atomic_private(&self.path, json.as_bytes())?;
        Ok(())
    }

    /// Consume `message_hash` (SHA-256 of the exact signing bytes).
    ///
    /// Fails with [`NonceStoreError::Replay`] when the hash was already
    /// consumed and has not expired. `expires_at_unix` should be the
    /// message's `expiration_time` (or `now + TTL` when absent).
    pub fn consume(
        &self,
        message_hash: &[u8; 32],
        expires_at_unix: u64,
    ) -> Result<(), NonceStoreError> {
        let mut map = self.load()?;
        let key = hex::encode(message_hash);
        if map.contains_key(&key) {
            return Err(NonceStoreError::Replay);
        }
        if map.len() >= MAX_NONCE_ENTRIES {
            // Oldest-expiring entry goes; the replay window stays bounded
            // instead of denying fresh logins (fail-closed on capacity).
            if let Some(oldest) = map.iter().min_by_key(|(_, exp)| *exp).map(|(k, _)| k.clone()) {
                map.remove(&oldest);
            }
        }
        map.insert(key, expires_at_unix.max(now_unix().saturating_add(1)));
        self.save(&map)
    }

    /// Returns `true` when `message_hash` is currently consumed (unexpired).
    pub fn is_consumed(&self, message_hash: &[u8; 32]) -> Result<bool, NonceStoreError> {
        let map = self.load()?;
        Ok(map.contains_key(&hex::encode(message_hash)))
    }

    /// Number of live (unexpired) entries. Tests / diagnostics only.
    pub fn len(&self) -> Result<usize, NonceStoreError> {
        Ok(self.load()?.len())
    }

    /// Returns `true` when no live (unexpired) entries are tracked.
    pub fn is_empty(&self) -> Result<bool, NonceStoreError> {
        Ok(self.load()?.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    fn tmp_store() -> (tempfile::TempDir, NonceStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = NonceStore::open(dir.path().join("siwx_nonces.json"));
        (dir, store)
    }

    fn hash_of(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    #[test]
    fn consume_then_replay_is_rejected() {
        let (_dir, store) = tmp_store();
        let h = hash_of(b"login message one");
        let exp = now_unix() + 3600;
        store.consume(&h, exp).expect("first consume");
        let err = store.consume(&h, exp).expect_err("replay");
        assert!(matches!(err, NonceStoreError::Replay));
        assert!(store.is_consumed(&h).expect("is_consumed"));
    }

    #[test]
    fn different_messages_do_not_collide() {
        let (_dir, store) = tmp_store();
        let exp = now_unix() + 3600;
        store.consume(&hash_of(b"message a"), exp).expect("a");
        store.consume(&hash_of(b"message b"), exp).expect("b");
        assert_eq!(store.len().expect("len"), 2);
    }

    #[test]
    fn expired_entries_are_garbage_collected() {
        let (_dir, store) = tmp_store();
        let past = now_unix().saturating_sub(10);
        // `consume` clamps expiry to now+1s minimum, so write an expired
        // entry through the file directly.
        let h = hash_of(b"old message");
        let mut map = HashMap::new();
        map.insert(hex::encode(h), past);
        store.save(&map).expect("save");
        // Load path GCs the expired entry: not consumed, len 0, and a fresh
        // consume of the same hash succeeds.
        assert!(!store.is_consumed(&h).expect("gc"));
        assert_eq!(store.len().expect("len"), 0);
        store.consume(&h, now_unix() + 3600).expect("re-consume");
    }

    #[test]
    fn corrupt_file_is_fail_closed() {
        let (_dir, store) = tmp_store();
        fs::write(&store.path, "{ not json").expect("write");
        let err = store.len().expect_err("corrupt");
        assert!(matches!(err, NonceStoreError::Corrupt { .. }), "got {err:?}");
    }

    #[test]
    fn capacity_evicts_oldest_instead_of_denying() {
        let (_dir, store) = tmp_store();
        let base = now_unix() + 3600;
        // Pre-fill to capacity in a single write (per-consume file
        // round-trips would be O(n^2)); expiries increase with `i`.
        let mut map = HashMap::new();
        for i in 0..MAX_NONCE_ENTRIES {
            let h = hash_of(format!("msg-{i}").as_bytes());
            map.insert(hex::encode(h), base + i as u64);
        }
        store.save(&map).expect("prefill");
        assert_eq!(store.len().expect("len"), MAX_NONCE_ENTRIES);
        // One more consume evicts the oldest (`msg-0`) and succeeds.
        let fresh = hash_of(b"fresh login");
        store.consume(&fresh, base + MAX_NONCE_ENTRIES as u64).expect("fresh");
        assert_eq!(store.len().expect("len"), MAX_NONCE_ENTRIES);
        assert!(store.is_consumed(&fresh).expect("fresh tracked"));
        assert!(
            !store.is_consumed(&hash_of(b"msg-0")).expect("oldest evicted"),
            "oldest entry must be evicted"
        );
    }
}
