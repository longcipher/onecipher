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
use tokio::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::prelude::*;

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
    /// In-flight registration challenges (UUID → PasskeyRegistration state).
    reg_challenges: Arc<Mutex<Vec<(Uuid, PasskeyRegistration)>>>,
    /// In-flight authentication challenges (UUID → PasskeyAuthentication state).
    auth_challenges: Arc<Mutex<Vec<(Uuid, PasskeyAuthentication)>>>,
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
            reg_challenges: Arc::new(Mutex::new(Vec::new())),
            auth_challenges: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Begin passkey registration ceremony.
    pub async fn register_begin(
        &self,
    ) -> Result<(CreationChallengeResponse, Uuid), webauthn_rs::prelude::WebauthnError> {
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
        challenges.push((user_id, reg_state));

        Ok((ccr, user_id))
    }

    /// Finish passkey registration ceremony and persist the new credential.
    pub async fn register_finish(
        &self,
        user_id: Uuid,
        response: &RegisterPublicKeyCredential,
    ) -> Result<StoredCredential, WebauthnError> {
        let mut challenges = self.reg_challenges.lock().await;
        let idx = challenges
            .iter()
            .position(|(id, _)| *id == user_id)
            .ok_or(WebauthnError::ChallengeNotFound)?;
        let (_, reg_state) = challenges.remove(idx);
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
    pub async fn login_begin(&self) -> Result<(RequestChallengeResponse, Uuid), WebauthnError> {
        let creds = self.load_credentials().await;
        if creds.is_empty() {
            return Err(WebauthnError::CredentialNotFound);
        }
        let passkeys: Vec<Passkey> = creds.into_iter().map(|c| c.credential).collect();

        let (rcr, auth_state) = self.webauthn.start_passkey_authentication(&passkeys)?;
        let challenge_id = Uuid::new_v4();

        let mut challenges = self.auth_challenges.lock().await;
        challenges.push((challenge_id, auth_state));

        Ok((rcr, challenge_id))
    }

    /// Finish passkey authentication ceremony.
    pub async fn login_finish(
        &self,
        challenge_id: Uuid,
        response: &PublicKeyCredential,
    ) -> Result<String, WebauthnError> {
        let mut challenges = self.auth_challenges.lock().await;
        let idx = challenges
            .iter()
            .position(|(id, _)| *id == challenge_id)
            .ok_or(WebauthnError::ChallengeNotFound)?;
        let (_, auth_state) = challenges.remove(idx);
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

    async fn save_credentials(&self, creds: &[StoredCredential]) -> Result<(), WebauthnError> {
        let file = CredentialFile { credentials: creds.to_vec() };
        let content = serde_json::to_string_pretty(&file)
            .map_err(|_| WebauthnError::InvalidClientDataType)?;
        tokio::fs::write(&self.credentials_path, content.as_bytes())
            .await
            .map_err(|_| WebauthnError::InvalidClientDataType)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(
                &self.credentials_path,
                std::fs::Permissions::from_mode(0o600),
            )
            .await;
        }
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
        assert!(!ccr.public_key.challenge.is_empty());
    }
}
