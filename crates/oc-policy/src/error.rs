//! Per-layer error type for `oc-policy` (thiserror 2.x, per Repo Standards).

use thiserror::Error;

/// Errors returned by `oc-policy` operations (I/O, serde, invalid input).
#[derive(Debug, Error)]
pub enum OcPolicyError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}
