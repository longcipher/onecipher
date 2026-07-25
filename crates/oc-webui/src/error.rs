//! Error types for oc-webui.

use thiserror::Error;

/// Web UI errors.
#[derive(Debug, Error)]
pub enum WebUiError {
    #[error("authentication required")]
    Unauthenticated,
    #[error("session expired")]
    SessionExpired,
    #[error("bootstrap token invalid or expired")]
    BootstrapInvalid,
    #[error("approval not found: {id}")]
    ApprovalNotFound { id: String },
    #[error("approval already resolved")]
    ApprovalAlreadyResolved,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
