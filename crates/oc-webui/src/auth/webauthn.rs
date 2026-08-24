//! WebAuthn registration and authentication via `webauthn-rs`.
//!
//! Credentials are persisted to `~/.onecipher/webauthn_passkeys.json` (mode 0600).
//! The server uses `http://localhost` as the Relying Party origin since the Web UI
//! is served over HTTP on loopback only.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// Maximum number of live challenges kept per ceremony kind (M-13).
const CHALLENGE_CAP: usize = 256;

/// Time-to-live for a single challenge, enforced when it is consumed (M-13).
const CHALLENGE_TTL: tokio::time::Duration = tokio::time::Duration::from_secs(120);

/// Failure modes of the bounded challenge stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    /// No live challenge under the given id (never issued or already consumed).
    Unknown,
    /// The challenge existed but its TTL elapsed before consumption.
    Expired,
    /// Begin rejected: the store is at capacity even after sweeping.
    StoreFull,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unknown => "challenge not found",
            Self::Expired => "challenge expired",
            Self::StoreFull => "too many pending challenges",
        })
    }
}

impl std::error::Error for ChallengeError {}

/// Errors surfaced by [`WebAuthnManager`] ceremonies.
#[derive(Debug, Error, PartialEq)]
pub enum WebAuthnError {
    #[error("no credentials registered")]
    NoCredentials,
    #[error("{0}")]
    Challenge(#[from] ChallengeError),
    #[error("webauthn protocol error: {0}")]
    Protocol(#[from] WebauthnError),
}

/// A single in-flight challenge with its creation stamp.
struct ChallengeEntry<S> {
    state: S,
    created_at: tokio::time::Instant,
}

/// Bounded store of in-flight challenges for one ceremony kind.
///
/// Entries expire after [`CHALLENGE_TTL`] (swept lazily on insert/take) and
/// the store holds at most [`CHALLENGE_CAP`] live entries, so unauthenticated
/// `begin` calls cannot grow memory without bound (M-13).
struct ChallengeStore<S> {
    entries: Vec<(Uuid, ChallengeEntry<S>)>,
}

impl<S> ChallengeStore<S> {
    fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Insert a fresh challenge stamped with the current tokio clock.
    ///
    /// Returns [`ChallengeError::StoreFull`] when the store is still at
    /// [`CHALLENGE_CAP`] live entries after sweeping expired ones.
    fn insert(&mut self, id: Uuid, state: S) -> Result<(), ChallengeError> {
        self.sweep_expired();
        if self.entries.len() >= CHALLENGE_CAP {
            return Err(ChallengeError::StoreFull);
        }
        self.entries.push((id, ChallengeEntry { state, created_at: tokio::time::Instant::now() }));
        Ok(())
    }

    /// Remove and return the challenge state for `id`.
    ///
    /// A challenge whose TTL elapsed yields [`ChallengeError::Expired`] —
    /// the same fail-closed outcome as an unknown id, but distinguishable
    /// for diagnostics. The entry is always removed once found.
    fn take(&mut self, id: &Uuid) -> Result<S, ChallengeError> {
        let now = tokio::time::Instant::now();
        let idx =
            self.entries.iter().position(|(eid, _)| eid == id).ok_or(ChallengeError::Unknown)?;
        let (_, entry) = self.entries.remove(idx);
        // Lazy sweep: drop every other entry past its TTL while we are here.
        self.entries.retain(|(_, e)| now.duration_since(e.created_at) < CHALLENGE_TTL);
        if now.duration_since(entry.created_at) >= CHALLENGE_TTL {
            return Err(ChallengeError::Expired);
        }
        Ok(entry.state)
    }

    /// Drop entries older than the TTL.
    fn sweep_expired(&mut self) {
        let now = tokio::time::Instant::now();
        self.entries.retain(|(_, e)| now.duration_since(e.created_at) < CHALLENGE_TTL);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Stored credential for a registered passkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: String,
    pub credential: Passkey,
    pub registered_at_unix: u64,
}

/// Persistent credential store.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CredentialFile {
    credentials: Vec<StoredCredential>,
}

/// WebAuthn manager handling registration and authentication ceremonies.
#[derive(Clone)]
pub struct WebAuthnManager {
    webauthn: Arc<Webauthn>,
    credentials_path: PathBuf,
    /// In-flight registration challenges (bounded, TTL-enforced).
    reg_challenges: Arc<Mutex<ChallengeStore<PasskeyRegistration>>>,
    /// In-flight authentication challenges (bounded, TTL-enforced).
    auth_challenges: Arc<Mutex<ChallengeStore<PasskeyAuthentication>>>,
}

impl WebAuthnManager {
    /// Create a new WebAuthn manager.
    ///
    /// `rp_id` is typically "localhost" for the local Web UI.
    /// `rp_origin` is the full origin URL (e.g., "http://localhost:PORT").
    pub fn new(
        state_dir: &Path,
        rp_origin: &url::Url,
    ) -> Result<Self, webauthn_rs::prelude::WebauthnError> {
        let rp_id = rp_origin.host_str().unwrap_or("localhost");
        let builder = WebauthnBuilder::new(rp_id, rp_origin)?;
        let webauthn = builder.rp_name("OneCipher").build()?;
        Ok(Self {
            webauthn: Arc::new(webauthn),
            credentials_path: state_dir.join("webauthn_passkeys.json"),
            reg_challenges: Arc::new(Mutex::new(ChallengeStore::new())),
            auth_challenges: Arc::new(Mutex::new(ChallengeStore::new())),
        })
    }

    /// Begin passkey registration ceremony.
    ///
    /// Fails with [`WebAuthnError::Challenge`] (`StoreFull`) when the bounded
    /// challenge store is at capacity even after sweeping expired entries.
    pub async fn register_begin(&self) -> Result<(CreationChallengeResponse, Uuid), WebAuthnError> {
        let user_id = Uuid::new_v4();
        let existing_creds = self.load_credentials().await;
        let exclude: Vec<CredentialID> =
            existing_creds.iter().map(|c| c.credential.cred_id().clone()).collect();

        let (ccr, reg_state) = self.webauthn.start_passkey_registration(
            user_id,
            "onecipher-user",
            "OneCipher User",
            Some(exclude),
        )?;

        let mut challenges = self.reg_challenges.lock().await;
        challenges.insert(user_id, reg_state)?;
        drop(challenges);

        Ok((ccr, user_id))
    }

    /// Finish passkey registration ceremony and persist the new credential.
    ///
    /// The challenge must still be live: expired or unknown ids fail closed
    /// with [`WebAuthnError::Challenge`].
    pub async fn register_finish(
        &self,
        user_id: Uuid,
        response: &RegisterPublicKeyCredential,
    ) -> Result<StoredCredential, WebAuthnError> {
        let mut challenges = self.reg_challenges.lock().await;
        let reg_state = challenges.take(&user_id)?;
        drop(challenges);

        let passkey = self.webauthn.finish_passkey_registration(response, &reg_state)?;
        let cred_id = hex::encode(passkey.cred_id().as_ref());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stored = StoredCredential {
            credential_id: cred_id,
            credential: passkey,
            registered_at_unix: now,
        };

        // Persist
        let mut all = self.load_credentials().await;
        all.push(stored.clone());
        self.save_credentials(&all).await?;

        Ok(stored)
    }

    /// Begin passkey authentication ceremony.
    ///
    /// Fails with [`WebAuthnError::Challenge`] (`StoreFull`) when the bounded
    /// challenge store is at capacity even after sweeping expired entries.
    pub async fn login_begin(&self) -> Result<(RequestChallengeResponse, Uuid), WebAuthnError> {
        let creds = self.load_credentials().await;
        if creds.is_empty() {
            return Err(WebAuthnError::NoCredentials);
        }
        let passkeys: Vec<Passkey> = creds.into_iter().map(|c| c.credential).collect();

        let (rcr, auth_state) = self.webauthn.start_passkey_authentication(&passkeys)?;
        let challenge_id = Uuid::new_v4();

        let mut challenges = self.auth_challenges.lock().await;
        challenges.insert(challenge_id, auth_state)?;
        drop(challenges);

        Ok((rcr, challenge_id))
    }

    /// Finish passkey authentication ceremony.
    ///
    /// The challenge must still be live: expired or unknown ids fail closed
    /// with [`WebAuthnError::Challenge`].
    pub async fn login_finish(
        &self,
        challenge_id: Uuid,
        response: &PublicKeyCredential,
    ) -> Result<String, WebAuthnError> {
        let mut challenges = self.auth_challenges.lock().await;
        let auth_state = challenges.take(&challenge_id)?;
        drop(challenges);

        let auth_result = self.webauthn.finish_passkey_authentication(response, &auth_state)?;
        let cred_id = hex::encode(auth_result.cred_id().as_ref());

        // Update credential counter
        let mut all = self.load_credentials().await;
        if let Some(stored) = all.iter_mut().find(|c| c.credential_id == cred_id) {
            stored.credential.update_credential(&auth_result);
            let _ = self.save_credentials(&all).await;
        }

        Ok(cred_id)
    }

    /// Check if any credentials are registered.
    pub async fn has_credentials(&self) -> bool {
        !self.load_credentials().await.is_empty()
    }

    async fn load_credentials(&self) -> Vec<StoredCredential> {
        match tokio::fs::read_to_string(&self.credentials_path).await {
            Ok(content) => serde_json::from_str::<CredentialFile>(&content)
                .map(|f| f.credentials)
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    async fn save_credentials(&self, creds: &[StoredCredential]) -> Result<(), WebAuthnError> {
        let file = CredentialFile { credentials: creds.to_vec() };
        let content = serde_json::to_string_pretty(&file)
            .map_err(|_| WebAuthnError::Protocol(WebauthnError::InvalidClientDataType))?;
        // Atomic + created at 0600. WebAuthn credentials must never be briefly
        // world-readable: they contain the credential ID and public key that
        // a nearby local attacker could replay.
        let p = self.credentials_path.clone();
        tokio::task::spawn_blocking(move || {
            oc_core::paths::write_atomic_private(&p, content.as_bytes())
        })
        .await
        .map_err(|_| WebAuthnError::Protocol(WebauthnError::InvalidClientDataType))?
        .map_err(|_| WebAuthnError::Protocol(WebauthnError::InvalidClientDataType))?;
        Ok(())
    }
}

impl std::fmt::Debug for WebAuthnManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebAuthnManager")
            .field("credentials_path", &self.credentials_path)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager(dir: &Path) -> WebAuthnManager {
        let origin = url::Url::parse("http://localhost:9090").unwrap();
        WebAuthnManager::new(dir, &origin).unwrap()
    }

    #[tokio::test]
    async fn no_credentials_initially() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = make_manager(dir.path());
        assert!(!mgr.has_credentials().await);
    }

    #[tokio::test]
    async fn login_begin_fails_with_no_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = make_manager(dir.path());
        let result = mgr.login_begin().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn register_begin_returns_challenge() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = make_manager(dir.path());
        let result = mgr.register_begin().await;
        assert!(result.is_ok());
        let (ccr, _user_id) = result.unwrap();
        // The challenge should be non-empty
        assert!(!ccr.public_key.challenge.is_empty(), "challenge must be non-empty");
    }

    // -----------------------------------------------------------------------
    // Bounded challenge stores (M-13)
    // -----------------------------------------------------------------------

    /// A syntactically-shaped but cryptographically bogus registration
    /// response. Challenge-store checks run before protocol verification,
    /// so this is enough to drive the consumption paths.
    fn dummy_registration_response() -> RegisterPublicKeyCredential {
        serde_json::from_str(
            r#"{
            "id": "dGVzdA",
            "rawId": "AQID",
            "type": "public-key",
            "response": {
                "attestationObject": "",
                "clientDataJSON": ""
            }
        }"#,
        )
        .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn store_take_after_ttl_reports_expired() {
        let mut store = ChallengeStore::<u8>::new();
        let id = Uuid::new_v4();
        store.insert(id, 7).unwrap();

        tokio::time::advance(CHALLENGE_TTL).await;
        assert_eq!(store.take(&id), Err(ChallengeError::Expired));
        assert_eq!(store.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn store_unknown_id_reports_unknown() {
        let mut store = ChallengeStore::<u8>::new();
        assert_eq!(store.take(&Uuid::new_v4()), Err(ChallengeError::Unknown));
    }

    #[tokio::test(start_paused = true)]
    async fn store_cap_rejects_until_entries_expire() {
        let mut store = ChallengeStore::<u8>::new();
        for _ in 0..CHALLENGE_CAP {
            store.insert(Uuid::new_v4(), 0).unwrap();
        }
        assert_eq!(store.insert(Uuid::new_v4(), 0), Err(ChallengeError::StoreFull));

        // Once the TTL elapses the lazy sweep frees room again.
        tokio::time::advance(CHALLENGE_TTL).await;
        store.insert(Uuid::new_v4(), 0).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn register_finish_rejects_expired_challenge() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = make_manager(dir.path());
        let (_ccr, user_id) = mgr.register_begin().await.unwrap();

        tokio::time::advance(CHALLENGE_TTL).await;
        let err = mgr.register_finish(user_id, &dummy_registration_response()).await.unwrap_err();
        assert_eq!(err, WebAuthnError::Challenge(ChallengeError::Expired));
    }

    #[tokio::test(start_paused = true)]
    async fn register_begin_rejects_at_cap() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = make_manager(dir.path());
        for _ in 0..CHALLENGE_CAP {
            mgr.register_begin().await.unwrap();
        }
        let err = mgr.register_begin().await.unwrap_err();
        assert_eq!(err, WebAuthnError::Challenge(ChallengeError::StoreFull));
    }

    #[tokio::test]
    async fn register_finish_consumes_challenge_once() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = make_manager(dir.path());
        let (_ccr, user_id) = mgr.register_begin().await.unwrap();

        // The bogus response fails protocol verification, but only AFTER the
        // challenge was consumed from the store.
        let err = mgr.register_finish(user_id, &dummy_registration_response()).await.unwrap_err();
        assert!(matches!(err, WebAuthnError::Protocol(_)));

        // A second attempt finds nothing: success removed the entry.
        let err = mgr.register_finish(user_id, &dummy_registration_response()).await.unwrap_err();
        assert_eq!(err, WebAuthnError::Challenge(ChallengeError::Unknown));
    }
}
