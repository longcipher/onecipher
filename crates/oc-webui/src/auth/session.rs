//! In-memory session store with auto-expiry.
//!
//! Sessions are stored in a `DashMap` keyed by session ID (UUID).
//! Each session has a configurable timeout and an activity-based extension.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use uuid::Uuid;

/// An authenticated session.
#[derive(Debug, Clone)]
pub struct AuthSession {
    /// Session identifier (set as cookie).
    pub id: String,
    /// WebAuthn credential ID that authenticated this session.
    pub credential_id: String,
    /// When this session was created.
    pub created_at: Instant,
    /// Last activity timestamp — extends the session.
    pub last_activity: Instant,
    /// Maximum idle time before auto-expiry.
    pub idle_timeout: Duration,
    /// Absolute session deadline (auto_lock_at feature).
    pub absolute_deadline: Option<Instant>,
}

impl AuthSession {
    /// Check if this session has expired.
    pub fn is_expired(&self) -> bool {
        if self.last_activity.elapsed() > self.idle_timeout {
            return true;
        }
        if let Some(deadline) = self.absolute_deadline {
            if Instant::now() > deadline {
                return true;
            }
        }
        false
    }

    /// Refresh the session's last activity to now.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

/// Thread-safe in-memory session store.
#[derive(Debug, Clone)]
pub struct SessionStore {
    sessions: Arc<DashMap<String, AuthSession>>,
    default_idle_timeout: Duration,
}

impl SessionStore {
    /// Create a new session store with the given default idle timeout.
    pub fn new(idle_timeout_secs: u64) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            default_idle_timeout: Duration::from_secs(idle_timeout_secs),
        }
    }

    /// Create a new session for the given credential.
    pub fn create_session(
        &self,
        credential_id: &str,
        absolute_deadline: Option<Instant>,
    ) -> AuthSession {
        let id = Uuid::new_v4().to_string();
        let now = Instant::now();
        let session = AuthSession {
            id: id.clone(),
            credential_id: credential_id.to_string(),
            created_at: now,
            last_activity: now,
            idle_timeout: self.default_idle_timeout,
            absolute_deadline,
        };
        self.sessions.insert(id, session.clone());
        session
    }

    /// Validate and refresh a session. Returns `Some(session)` if valid.
    pub fn validate(&self, session_id: &str) -> Option<AuthSession> {
        let mut entry = self.sessions.get_mut(session_id)?;
        if entry.is_expired() {
            drop(entry);
            self.sessions.remove(session_id);
            return None;
        }
        entry.touch();
        Some(entry.clone())
    }

    /// Remove a session (logout).
    pub fn remove(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    /// Remove all expired sessions (garbage collection).
    pub fn gc(&self) -> usize {
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|entry| entry.value().is_expired())
            .map(|entry| entry.key().clone())
            .collect();
        let count = expired.len();
        for id in expired {
            self.sessions.remove(&id);
        }
        count
    }

    /// Remove every session (auto-lock / lock trigger).
    ///
    /// Distinct from [`Self::gc`]: `gc` only drops sessions whose timeout has
    /// elapsed, while `destroy_all` forces the whole vault lock immediately.
    pub fn destroy_all(&self) -> usize {
        let count = self.sessions.len();
        self.sessions.clear();
        count
    }

    /// Number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the session store is empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_validate_session() {
        let store = SessionStore::new(1800);
        let session = store.create_session("cred-1", None);

        let validated = store.validate(&session.id);
        assert!(validated.is_some());
        assert_eq!(validated.unwrap().credential_id, "cred-1");
    }

    #[test]
    fn expired_session_rejected() {
        let store = SessionStore::new(0); // 0 second timeout = immediate expiry
        let session = store.create_session("cred-1", None);

        // Sleep briefly to ensure timeout elapses
        std::thread::sleep(Duration::from_millis(10));

        let validated = store.validate(&session.id);
        assert!(validated.is_none());
    }

    #[test]
    fn remove_session() {
        let store = SessionStore::new(1800);
        let session = store.create_session("cred-1", None);
        assert_eq!(store.len(), 1);

        store.remove(&session.id);
        assert_eq!(store.len(), 0);
        assert!(store.validate(&session.id).is_none());
    }

    #[test]
    fn gc_removes_expired() {
        let store = SessionStore::new(0);
        store.create_session("cred-1", None);
        store.create_session("cred-2", None);

        std::thread::sleep(Duration::from_millis(10));

        let removed = store.gc();
        assert_eq!(removed, 2);
        assert!(store.is_empty());
    }

    #[test]
    fn absolute_deadline_expires_session() {
        let store = SessionStore::new(3600);
        // Deadline in the past
        let deadline = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let session = store.create_session("cred-1", Some(deadline));

        let validated = store.validate(&session.id);
        assert!(validated.is_none());
    }
}
