//! Persist WC session state to disk (JSON).
//!
//! File: `<state_dir>/wc_sessions.json` (mode 0600).

use std::{path::PathBuf, sync::Mutex};

use oc_walletconnect::WcSession;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct SessionStore {
    path: PathBuf,
    /// Lazily-loaded in-memory index; `None` means "not yet loaded".
    /// Guarded by the mutex so concurrent `upsert`/`save`/`load` callers
    /// cannot lose updates (see [`SessionStore::upsert`]).
    cache: Mutex<Option<Vec<WcSession>>>,
}

impl SessionStore {
    pub fn open(state_dir: &str) -> Result<Self, SessionStoreError> {
        let path = PathBuf::from(state_dir).join("wc_sessions.json");
        Ok(Self { path, cache: Mutex::new(None) })
    }

    pub fn load(&self) -> Result<Vec<WcSession>, SessionStoreError> {
        let mut cache = self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(v) = &*cache {
            // Serve from the in-memory index (clone so callers can't mutate it).
            return Ok(v.clone());
        }
        let v = if self.path.exists() {
            let bytes = std::fs::read(&self.path)?;
            serde_json::from_slice(&bytes)?
        } else {
            Vec::new()
        };
        *cache = Some(v.clone());
        Ok(v)
    }

    pub fn save(&self, sessions: &[WcSession]) -> Result<(), SessionStoreError> {
        let bytes = serde_json::to_vec_pretty(sessions)?;
        // Atomic + created at 0600. WalletConnect session records contain
        // pairing topics and symmetric keys, so they must never be briefly
        // world-readable the way `fs::write` + `set_permissions` left them.
        oc_core::paths::write_atomic_private(&self.path, &bytes)?;
        // Keep the in-memory index coherent with what was just written.
        *self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(sessions.to_vec());
        Ok(())
    }

    /// Lock the cache, lazily loading it from disk (or an empty vec) on first use.
    fn cached(&self) -> std::sync::MutexGuard<'_, Option<Vec<WcSession>>> {
        let mut cache = self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.is_none() {
            let v = if self.path.exists() {
                let bytes = std::fs::read(&self.path).unwrap_or_default();
                serde_json::from_slice(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            };
            *cache = Some(v);
        }
        cache
    }

    /// Atomically insert-or-replace a single session without a caller-driven
    /// read-modify-write of the entire list.
    ///
    /// The `Mutex` makes the find-or-push + disk write atomic with respect to
    /// other `upsert`/`save` callers, eliminating the lost-update race that the
    /// previous `load`/`modify`/`save` pattern in `run_server_controlled_*` had
    /// under concurrent pairing injection.
    pub fn upsert(&self, session: &WcSession) -> Result<(), SessionStoreError> {
        let mut cache = self.cached();
        // `cached()` always populates the cache; get_or_insert_with keeps this
        // total (no panic path) even if that invariant ever regresses.
        let all = cache.get_or_insert_with(Vec::new);
        if let Some(existing) = all.iter_mut().find(|s| s.topic == session.topic) {
            *existing = session.clone();
        } else {
            all.push(session.clone());
        }
        // Snapshot then **drop the cache lock** before calling `save`, which
        // re-locks the same (non-reentrant) `Mutex`. Holding it here would
        // deadlock the calling thread. `save` re-populates the cache from the
        // snapshot, so the index stays coherent.
        let snapshot = all.clone();
        drop(cache);
        self.save(&snapshot)
    }

    #[cfg(test)]
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use oc_walletconnect::{WcSessionState, WcSymKeyHex};

    use super::*;

    fn sample_session(topic: &str) -> WcSession {
        WcSession {
            topic: topic.to_string(),
            sym_key: WcSymKeyHex::new("0xabcdef".to_string()),
            state: WcSessionState::Propose,
            expiry_unix: 9999999999,
            namespaces: Vec::new(),
            methods: vec!["personal_sign".to_string()],
            dapp_origin: None,
            dapp_name: None,
            created_at_unix: 1000000000,
        }
    }

    #[test]
    fn open_returns_store_with_correct_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(dir.path().to_str().unwrap()).unwrap();
        assert!(store.path().ends_with("wc_sessions.json"));
    }

    #[test]
    fn load_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(dir.path().to_str().unwrap()).unwrap();
        let sessions = store.load().unwrap();
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(dir.path().to_str().unwrap()).unwrap();
        let input = vec![sample_session("topic-1"), sample_session("topic-2")];
        store.save(&input).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].topic, "topic-1");
        assert_eq!(loaded[1].topic, "topic-2");
    }

    #[test]
    fn save_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        let store = SessionStore::open(nested.to_str().unwrap()).unwrap();
        store.save(&[]).unwrap();
        assert!(store.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(dir.path().to_str().unwrap()).unwrap();
        store.save(&[sample_session("t1")]).unwrap();
        let meta = std::fs::metadata(store.path()).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn load_returns_error_on_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(dir.path().to_str().unwrap()).unwrap();
        std::fs::write(store.path(), "not json").unwrap();
        let result = store.load();
        assert!(result.is_err());
    }

    #[test]
    fn save_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(dir.path().to_str().unwrap()).unwrap();
        store.save(&[sample_session("old")]).unwrap();
        store.save(&[sample_session("new1"), sample_session("new2")]).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].topic, "new1");
    }

    #[test]
    fn upsert_inserts_then_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(dir.path().to_str().unwrap()).unwrap();
        store.upsert(&sample_session("t1")).unwrap();
        store.upsert(&sample_session("t2")).unwrap();
        store.upsert(&sample_session("t1")).unwrap(); // replace, not duplicate
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 2);
        // t1 should appear exactly once (no duplicate on re-insert).
        assert_eq!(loaded.iter().filter(|s| s.topic == "t1").count(), 1);
    }
}
