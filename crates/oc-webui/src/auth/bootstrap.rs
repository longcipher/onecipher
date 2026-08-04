//! One-time bootstrap token for first-time WebAuthn registration.
//!
//! Generated on daemon start (if no credentials exist), valid for 5 minutes,
//! single-use. Written to `~/.onecipher/bootstrap_token` (mode 0600).

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

/// TTL for bootstrap tokens: 5 minutes.
const BOOTSTRAP_TTL: Duration = Duration::from_secs(300);

/// A one-time bootstrap token for initial WebAuthn registration.
#[derive(Debug, Clone)]
pub struct BootstrapToken {
    inner: Arc<Mutex<TokenState>>,
    path: PathBuf,
}

#[derive(Debug)]
struct TokenState {
    token: Option<String>,
    created_at: Option<Instant>,
    consumed: bool,
}

impl BootstrapToken {
    /// Create a new bootstrap token manager bound to the given state directory.
    pub fn new(state_dir: &Path) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TokenState {
                token: None,
                created_at: None,
                consumed: false,
            })),
            path: state_dir.join("bootstrap_token"),
        }
    }

    /// Generate a fresh bootstrap token. Overwrites any previous token.
    pub async fn generate(&self) -> std::io::Result<String> {
        let token = uuid::Uuid::new_v4().to_string();
        let mut state = self.inner.lock().await;
        state.token = Some(token.clone());
        state.created_at = Some(Instant::now());
        state.consumed = false;

        // Persist to filesystem atomically at 0600. A bootstrap token written
        // at the umask-derived mode gives every local user one-time admin.
        let p = self.path.clone();
        let t = token.clone();
        tokio::task::spawn_blocking(move || oc_core::paths::write_atomic_private(&p, t.as_bytes()))
            .await??;

        Ok(token)
    }

    /// Validate and consume the bootstrap token. Returns `true` if valid.
    ///
    /// A token is valid only if:
    /// - It matches the stored token
    /// - It has not expired (5 minute TTL)
    /// - It has not already been consumed
    pub async fn validate_and_consume(&self, candidate: &str) -> bool {
        let mut state = self.inner.lock().await;
        if state.consumed {
            return false;
        }
        let Some(ref stored) = state.token else {
            return false;
        };
        if stored != candidate {
            return false;
        }
        let Some(created_at) = state.created_at else {
            return false;
        };
        if created_at.elapsed() > BOOTSTRAP_TTL {
            return false;
        }
        state.consumed = true;
        // Remove the file after consumption
        let _ = tokio::fs::remove_file(&self.path).await;
        true
    }

    /// Check if a bootstrap token exists and is not yet expired (without consuming).
    pub async fn is_valid(&self) -> bool {
        let state = self.inner.lock().await;
        if state.consumed {
            return false;
        }
        let Some(ref _token) = state.token else {
            return false;
        };
        let Some(created_at) = state.created_at else {
            return false;
        };
        created_at.elapsed() <= BOOTSTRAP_TTL
    }

    /// Return the file path where the token is persisted.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generate_and_validate() {
        let dir = tempfile::tempdir().unwrap();
        let bt = BootstrapToken::new(dir.path());
        let token = bt.generate().await.unwrap();

        assert!(bt.is_valid().await);
        assert!(bt.validate_and_consume(&token).await);
        // Second consumption fails
        assert!(!bt.validate_and_consume(&token).await);
    }

    #[tokio::test]
    async fn wrong_token_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let bt = BootstrapToken::new(dir.path());
        let _token = bt.generate().await.unwrap();

        assert!(!bt.validate_and_consume("wrong-token").await);
    }

    #[tokio::test]
    async fn no_token_generated_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let bt = BootstrapToken::new(dir.path());
        assert!(!bt.is_valid().await);
        assert!(!bt.validate_and_consume("anything").await);
    }
}
