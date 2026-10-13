//! Daemon-side unlocked sessions for the OCWP interactive end (extension).
//!
//! A session binds a wallet + HD index + the owner passphrase (held in
//! `Zeroizing` memory, process-local only) plus the selected policy ids.
//! Sessions carry TTLs (absolute + idle); expiry forces re-unlock in the
//! client (design doc §3.5 / INV-13).

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use dashmap::DashMap;
use zeroize::Zeroizing;

use super::errors::OcwpError;

/// Session lifetime settings (seconds).
#[derive(Debug, Clone, Copy)]
pub(crate) struct SessionSettings {
    /// Absolute lifetime from creation.
    pub ttl_secs: u64,
    /// Idle timeout; refreshed on every validated request.
    pub idle_secs: u64,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self { ttl_secs: 900, idle_secs: 300 }
    }
}

/// An unlocked session. The passphrase is the only sensitive field; it lives
/// in process memory only and is never serialized or logged.
#[derive(Clone)]
pub(crate) struct SessionEntry {
    pub session_id: String,
    pub wallet: String,
    pub wallet_id: String,
    pub index: u32,
    pub passphrase: Arc<Zeroizing<String>>,
    /// Policy ids selected at unlock (empty = all policies in the vault).
    pub policy_ids: Vec<String>,
    /// `chrome-extension://<id>` origin that created this session. A session
    /// is only usable from the origin that unlocked it (INV-9 origin pinning):
    /// a second allowlisted extension must not be able to drive a session it
    /// never authenticated.
    pub origin: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_activity: u64,
}

/// Manual `Debug` impl that never renders the passphrase or session id
/// (INV-11: no secrets in logs).
impl std::fmt::Debug for SessionEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionEntry")
            .field("session_id", &"<redacted>")
            .field("wallet_id", &self.wallet_id)
            .field("origin", &self.origin)
            .field("index", &self.index)
            .field("policy_ids", &self.policy_ids)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("last_activity", &self.last_activity)
            .finish_non_exhaustive()
    }
}

/// In-memory session store with TTL enforcement.
pub(crate) struct SessionStore {
    sessions: DashMap<String, SessionEntry>,
    settings: SessionSettings,
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

impl SessionStore {
    pub(crate) fn new(settings: SessionSettings) -> Self {
        Self { sessions: DashMap::new(), settings }
    }

    /// Mint a new session and return its id (32 random bytes, hex-encoded).
    pub(crate) fn create(
        &self,
        wallet: String,
        wallet_id: String,
        index: u32,
        passphrase: Arc<Zeroizing<String>>,
        policy_ids: Vec<String>,
        origin: String,
    ) -> Result<String, OcwpError> {
        let mut raw = [0u8; 32];
        // Kernel CSPRNG; the error path is unreachable on any healthy OS but
        // must not panic in a server loop.
        getrandom::fill(&mut raw).map_err(|_| OcwpError::internal("OS RNG unavailable"))?;
        let session_id = hex::encode(raw);
        let now = now_unix();
        let entry = SessionEntry {
            session_id: session_id.clone(),
            wallet,
            wallet_id,
            index,
            passphrase,
            policy_ids,
            origin,
            created_at: now,
            expires_at: now.saturating_add(self.settings.ttl_secs),
            last_activity: now,
        };
        self.sessions.insert(session_id.clone(), entry);
        Ok(session_id)
    }

    /// Validate a session id, refresh its idle window, and enforce the
    /// origin binding: a session minted by extension A is unusable from
    /// extension B (INV-9).
    ///
    /// Expired (absolute or idle) sessions are removed and reported as
    /// `4100` — fail-closed, never silently extended.
    pub(crate) fn touch_for_origin(
        &self,
        session_id: &str,
        origin: &str,
    ) -> Result<SessionEntry, OcwpError> {
        let entry = self.touch(session_id)?;
        // An empty stored origin means the session predates origin pinning;
        // refuse it rather than treating it as a wildcard.
        if entry.origin.is_empty() || !entry.origin.eq_ignore_ascii_case(origin) {
            return Err(OcwpError::unauthorized(
                "session was not unlocked by this extension origin",
            ));
        }
        Ok(entry)
    }

    /// Validate a session id and refresh its idle window.
    ///
    /// Expired (absolute or idle) sessions are removed and reported as
    /// `4100` — fail-closed, never silently extended.
    pub(crate) fn touch(&self, session_id: &str) -> Result<SessionEntry, OcwpError> {
        let now = now_unix();
        let mut entry = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| OcwpError::unauthorized("unknown or expired session"))?;
        if now >= entry.expires_at ||
            now.saturating_sub(entry.last_activity) >= self.settings.idle_secs
        {
            drop(entry);
            self.sessions.remove(session_id);
            return Err(OcwpError::unauthorized("session expired"));
        }
        entry.last_activity = now;
        Ok(entry.clone())
    }

    /// Lock a single session. Returns whether it existed.
    pub(crate) fn lock(&self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// Lock every session bound to a wallet (vault lock / wallet deletion).
    #[allow(dead_code)] // wired up when daemon-side vault-lock events land
    pub(crate) fn lock_wallet(&self, wallet_id: &str) {
        self.sessions.retain(|_, entry| entry.wallet_id != wallet_id);
    }

    /// Number of live sessions (diagnostics/tests).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.sessions.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(store: &SessionStore, wallet_id: &str) -> String {
        store
            .create(
                "default".into(),
                wallet_id.into(),
                0,
                Arc::new(Zeroizing::new("pass".into())),
                Vec::new(),
                EXT_A.to_string(),
            )
            .expect("create session")
    }

    const EXT_A: &str = "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EXT_B: &str = "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn create_touch_lock_round_trip() {
        let store = SessionStore::new(SessionSettings::default());
        let id = entry(&store, "w1");
        assert_eq!(store.len(), 1);
        assert!(store.touch(&id).is_ok());
        assert!(store.lock(&id));
        assert!(store.touch(&id).is_err());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn absolute_ttl_expires_fail_closed() {
        let store = SessionStore::new(SessionSettings { ttl_secs: 0, idle_secs: 300 });
        let id = entry(&store, "w1");
        // ttl_secs = 0 → expires_at == created_at; any `now >= expires_at` fails.
        let err = store.touch(&id).expect_err("zero-ttl session must expire");
        assert_eq!(err.code, super::super::errors::CODE_UNAUTHORIZED);
        assert_eq!(store.len(), 0, "expired session must be evicted");
    }

    #[test]
    fn idle_ttl_expires_fail_closed() {
        let store = SessionStore::new(SessionSettings { ttl_secs: 900, idle_secs: 0 });
        let id = entry(&store, "w1");
        assert!(store.touch(&id).is_err(), "zero idle window must expire");
    }

    #[test]
    fn lock_wallet_invalidates_only_that_wallet() {
        let store = SessionStore::new(SessionSettings::default());
        let a = entry(&store, "w1");
        let b = entry(&store, "w2");
        assert!(!store.is_empty());
        store.lock_wallet("w1");
        assert!(store.touch(&a).is_err());
        assert!(store.touch(&b).is_ok());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn session_ids_are_unique_and_long() {
        let store = SessionStore::new(SessionSettings::default());
        let a = entry(&store, "w1");
        let b = entry(&store, "w1");
        assert_ne!(a, b);
        assert_eq!(a.len(), 64, "session id must be 32 bytes hex-encoded");
    }

    #[test]
    fn session_is_bound_to_the_origin_that_unlocked_it() {
        let store = SessionStore::new(SessionSettings::default());
        let id = entry(&store, "w1");
        // The unlocking origin works.
        assert!(store.touch_for_origin(&id, EXT_A).is_ok());
        // A different (also allowlisted) extension must not reuse it.
        let err = store
            .touch_for_origin(&id, EXT_B)
            .expect_err("foreign origin must not drive the session");
        assert_eq!(err.code, super::super::errors::CODE_UNAUTHORIZED);
        // Origin comparison is case-insensitive on the scheme/host (Chrome
        // always lowercases the id), and a web origin never matches.
        assert!(store.touch_for_origin(&id, EXT_A.to_ascii_lowercase().as_str()).is_ok());
        assert!(store.touch_for_origin(&id, "https://dapp.example").is_err());
        // The session survives a rejected attempt — only expiry/lock evict it.
        assert!(store.touch_for_origin(&id, EXT_A).is_ok());
    }
}
