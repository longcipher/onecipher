//! Persist WC session state to disk (JSON).
//!
//! File: `<state_dir>/wc_sessions.json` (mode 0600).

use std::path::PathBuf;

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
}

impl SessionStore {
    pub fn open(state_dir: &str) -> Result<Self, SessionStoreError> {
        let path = PathBuf::from(state_dir).join("wc_sessions.json");
        Ok(Self { path })
    }

    pub fn load(&self) -> Result<Vec<WcSession>, SessionStoreError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let bytes = std::fs::read(&self.path)?;
        let v: Vec<WcSession> = serde_json::from_slice(&bytes)?;
        Ok(v)
    }

    pub fn save(&self, sessions: &[WcSession]) -> Result<(), SessionStoreError> {
        let bytes = serde_json::to_vec_pretty(sessions)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.path, perms)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use oc_walletconnect::WcSessionState;

    use super::*;

    fn sample_session(topic: &str) -> WcSession {
        WcSession {
            topic: topic.to_string(),
            sym_key: "0xabcdef".to_string(),
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
        assert!(sessions.is_empty());
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
}
