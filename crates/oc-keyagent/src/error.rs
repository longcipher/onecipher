//! Key-Agent error types.

use thiserror::Error;

/// Top-level error for the Key-Agent server.
#[derive(Debug, Error)]
pub enum KeyAgentError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame error: {0}")]
    Frame(#[from] crate::frame::FrameError),
    #[error("prost decode error: {0}")]
    ProstDecode(#[from] prost::DecodeError),
    #[error("not yet implemented: {0}")]
    NotImplemented(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("internal error: {0}")]
    Internal(String),
    /// T12 sandbox hardening failure (seccomp / capset / prctl).
    #[error("sandbox error: {0}")]
    Sandbox(String),
}
