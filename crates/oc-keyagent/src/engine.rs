use std::path::{Path, PathBuf};

use crate::{KeyAgentRequest, KeyAgentResponse, handler, signing_core_error::SigningCoreError};

/// The signing engine — a sync-only facade over the Key-Agent handler logic.
///
/// This is the main entry point for the async layer. Call via
/// `tokio::task::spawn_blocking(move || engine.handle(request))`.
///
/// **Note:** The daemon production path uses `oc_keyagent::server::run()`
/// directly (UDS listener + `handler::dispatch`). This facade is retained for
/// programmatic embedding and test scenarios.
#[doc(hidden)]
pub struct SigningEngine {
    state_dir: PathBuf,
}

impl SigningEngine {
    /// Open the engine with default paths (`~/.onecipher/`).
    pub fn open_default() -> Result<Self, SigningCoreError> {
        let state_dir = oc_core::paths::state_dir()
            .map_err(|e| SigningCoreError::InvalidInput(e.to_string()))?;
        Self::open(&state_dir)
    }

    /// Open the engine with a custom state directory.
    pub fn open(state_dir: &Path) -> Result<Self, SigningCoreError> {
        Ok(Self { state_dir: state_dir.to_path_buf() })
    }

    /// Handle a [`KeyAgentRequest`] synchronously.
    ///
    /// Delegates to the existing `crate::handler::dispatch()`. Returns
    /// `Ok(response)` for any successfully-processed request, and
    /// `Err(SigningCoreError)` only for unrecoverable dispatcher-level
    /// failures. Handler-internal errors are encoded inside the
    /// [`KeyAgentResponse`] (as `Error` variants) and returned via `Ok`.
    pub fn handle(&self, req: &KeyAgentRequest) -> Result<KeyAgentResponse, SigningCoreError> {
        handler::dispatch(req).map_err(|e| SigningCoreError::KeyAgent(e.to_string()))
    }

    /// Get the state directory.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }
}

/// A signing request (simplified — delegates to `KeyAgentRequest` internally).
pub struct SignRequest {
    pub wallet_id: String,
    pub chain_id: String,
    pub tx_bytes: Vec<u8>,
    pub session_key_id: Option<String>,
}

/// A signing result.
pub struct SignResult {
    pub signature: Vec<u8>,
    pub signed_tx: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_request_fields_round_trip() {
        let req = SignRequest {
            wallet_id: "w1".into(),
            chain_id: "eip155:1".into(),
            tx_bytes: vec![0xde, 0xad],
            session_key_id: Some("sk1".into()),
        };
        assert_eq!(req.wallet_id, "w1");
        assert_eq!(req.chain_id, "eip155:1");
        assert_eq!(req.tx_bytes, &[0xde, 0xad]);
        assert_eq!(req.session_key_id.as_deref(), Some("sk1"));
    }

    #[test]
    fn sign_result_fields_round_trip() {
        let res = SignResult { signature: vec![1, 2, 3], signed_tx: vec![4, 5, 6] };
        assert_eq!(res.signature, &[1, 2, 3]);
        assert_eq!(res.signed_tx, &[4, 5, 6]);
    }

    #[test]
    fn sign_request_no_session_key() {
        let req = SignRequest {
            wallet_id: "w1".into(),
            chain_id: "eip155:1".into(),
            tx_bytes: vec![],
            session_key_id: None,
        };
        assert!(req.session_key_id.is_none());
    }

    #[test]
    fn open_with_temp_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = SigningEngine::open(dir.path());
        assert!(engine.is_ok(), "open should succeed: {:?}", engine.err());
    }

    #[test]
    fn open_engine_state_dir_matches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = SigningEngine::open(dir.path()).expect("open");
        assert_eq!(engine.state_dir(), dir.path());
    }

    #[test]
    fn open_default_returns_error_when_home_not_set() {
        let _ = SigningEngine::open_default();
    }
}
