//! Error type for `SessionKeyProvider` operations.

use thiserror::Error;

/// Error type for `SessionKeyProvider` operations.
///
/// `Clone` is derived so that [`crate::rpc::MockRpcClient`] can store and return
/// `Result<_, SessionKeyError>` responses without re-allocating the error path.
#[derive(Debug, Clone, Error)]
pub enum SessionKeyError {
    #[error("on-chain RPC failed: {0}")]
    RpcFailed(String),
    #[error("session key not found: {0}")]
    NotFound(String),
    #[error("session key already revoked: {0}")]
    AlreadyRevoked(String),
    #[error("session key expired: {0}")]
    Expired(String),
    #[error("invalid payload: {0}")]
    InvalidPayload(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("chain mismatch: expected {expected}, got {actual}")]
    ChainMismatch { expected: String, actual: String },
    #[error("policy merkle root computation failed: {0}")]
    MerkleFailed(String),
    #[error("mock provider: {0}")]
    Mock(String),
}
