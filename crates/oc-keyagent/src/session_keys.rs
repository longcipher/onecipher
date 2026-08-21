//! Persistent session-key registry (create/revoke lifecycle).
//!
//! Backs the `CreateSessionKey` / `RevokeSessionKey` Key-Agent RPCs with real
//! state so that (a) issued keys survive daemon restarts and (b) revocation
//! has observable effect: signing handlers consult
//! [`SessionKeyStore::is_active`] whenever a request carries a non-empty
//! `session_key_id`.
//!
//! Stored as a JSON map at `~/.onecipher/session_keys.json` (mode 0600,
//! parent dir 0700) — same layout conventions as `passkey::PasskeyPubkeyStore`.
//!
//! Per R56: synchronous std only, NO tokio / async.

use std::{collections::HashMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum SessionKeyStoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HOME not set")]
    HomeNotSet,
    #[error(
        "session-key store at {path} is corrupt: {detail} — restore it from a backup or remove \
         the file"
    )]
    Corrupt { path: String, detail: String },
    #[error("session key already exists: {0}")]
    AlreadyExists(String),
    #[error("session key not found: {0}")]
    NotFound(String),
}

/// Lifecycle status of a registered session key.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionKeyStatus {
    Active,
    Revoked,
}

/// One persisted session-key record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionKeyRecord {
    pub session_key_id: String,
    pub label: String,
    pub status: SessionKeyStatus,
    pub created_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix: Option<u64>,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// File-backed registry of issued session keys.
pub struct SessionKeyStore {
    path: PathBuf,
}

impl SessionKeyStore {
    /// Open the default store at `~/.onecipher/session_keys.json`.
    pub fn open_default() -> Result<Self, SessionKeyStoreError> {
        let path = oc_core::paths::state_path("session_keys.json")
            .map_err(|_| SessionKeyStoreError::HomeNotSet)?;
        Ok(Self { path })
    }

    /// Open a store at a specific path.
    pub fn open(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load the full record map. Missing file = empty map; a parse failure is
    /// an explicit [`SessionKeyStoreError::Corrupt`] (fail-closed).
    fn load(&self) -> Result<HashMap<String, SessionKeyRecord>, SessionKeyStoreError> {
        match fs::read_to_string(&self.path) {
            Ok(contents) if contents.trim().is_empty() => Ok(HashMap::new()),
            Ok(contents) => {
                serde_json::from_str(&contents).map_err(|e| SessionKeyStoreError::Corrupt {
                    path: self.path.display().to_string(),
                    detail: e.to_string(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Persist the full record map atomically with mode 0600.
    fn save(&self, map: &HashMap<String, SessionKeyRecord>) -> Result<(), SessionKeyStoreError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let json = serde_json::to_string_pretty(map)?;
        oc_core::paths::write_atomic_private(&self.path, json.as_bytes())?;
        Ok(())
    }

    /// Register a new session key. Errors if the id already exists.
    pub fn create(
        &self,
        mut record: SessionKeyRecord,
    ) -> Result<SessionKeyRecord, SessionKeyStoreError> {
        let mut map = self.load()?;
        if map.contains_key(&record.session_key_id) {
            return Err(SessionKeyStoreError::AlreadyExists(record.session_key_id));
        }
        record.status = SessionKeyStatus::Active;
        record.revoked_at_unix = None;
        map.insert(record.session_key_id.clone(), record.clone());
        self.save(&map)?;
        Ok(record)
    }

    /// Look up a record by id.
    pub fn get(
        &self,
        session_key_id: &str,
    ) -> Result<Option<SessionKeyRecord>, SessionKeyStoreError> {
        Ok(self.load()?.get(session_key_id).cloned())
    }

    /// Whether `id` refers to an existing, non-revoked session key.
    pub fn is_active(&self, session_key_id: &str) -> Result<bool, SessionKeyStoreError> {
        Ok(self.load()?.get(session_key_id).is_some_and(|r| r.status == SessionKeyStatus::Active))
    }

    /// Revoke a session key. Idempotent for already-revoked keys; errors on
    /// unknown ids.
    pub fn revoke(&self, session_key_id: &str) -> Result<SessionKeyRecord, SessionKeyStoreError> {
        let mut map = self.load()?;
        let record = map
            .get_mut(session_key_id)
            .ok_or_else(|| SessionKeyStoreError::NotFound(session_key_id.to_string()))?;
        if record.status != SessionKeyStatus::Revoked {
            record.status = SessionKeyStatus::Revoked;
            record.revoked_at_unix = Some(now_unix());
        }
        let revoked = record.clone();
        self.save(&map)?;
        Ok(revoked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str) -> SessionKeyRecord {
        SessionKeyRecord {
            session_key_id: id.to_string(),
            label: "test".to_string(),
            status: SessionKeyStatus::Active,
            created_at_unix: 1_700_000_000,
            revoked_at_unix: None,
        }
    }

    #[test]
    fn create_get_is_active_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionKeyStore::open(dir.path().join("session_keys.json"));

        store.create(rec("sk-1")).unwrap();
        assert!(store.is_active("sk-1").unwrap());
        assert_eq!(store.get("sk-1").unwrap().unwrap().label, "test");
        assert!(!store.is_active("sk-other").unwrap());
    }

    #[test]
    fn double_create_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionKeyStore::open(dir.path().join("session_keys.json"));
        store.create(rec("sk-dup")).unwrap();
        assert!(matches!(
            store.create(rec("sk-dup")).unwrap_err(),
            SessionKeyStoreError::AlreadyExists(_)
        ));
    }

    #[test]
    fn revoke_flips_status_and_sets_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionKeyStore::open(dir.path().join("session_keys.json"));
        store.create(rec("sk-r")).unwrap();

        let revoked = store.revoke("sk-r").unwrap();
        assert_eq!(revoked.status, SessionKeyStatus::Revoked);
        assert!(revoked.revoked_at_unix.is_some());
        assert!(!store.is_active("sk-r").unwrap());

        // Re-revoke is idempotent; unknown ids error.
        store.revoke("sk-r").unwrap();
        assert!(matches!(
            store.revoke("sk-missing").unwrap_err(),
            SessionKeyStoreError::NotFound(_)
        ));
    }

    #[test]
    fn records_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session_keys.json");
        {
            let store = SessionKeyStore::open(path.clone());
            store.create(rec("sk-persist")).unwrap();
        }
        let reopened = SessionKeyStore::open(path);
        assert!(reopened.is_active("sk-persist").unwrap());
    }

    #[test]
    fn corrupt_store_is_explicit_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session_keys.json");
        std::fs::write(&path, b"not json").unwrap();
        let store = SessionKeyStore::open(path);
        assert!(matches!(store.is_active("x").unwrap_err(), SessionKeyStoreError::Corrupt { .. }));
    }
}
