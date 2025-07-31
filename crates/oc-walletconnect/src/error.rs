//! WalletConnect v2 error types.

use thiserror::Error;

/// Top-level error for all `oc-walletconnect` operations.
#[derive(Debug, Error)]
pub enum WcError {
    #[error("invalid pairing URI: {0}")]
    InvalidUri(String),

    #[error("invalid WC message: {0}")]
    InvalidMessage(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("JSON-RPC error: code={code} message={message}")]
    JsonRpc { code: i64, message: String },

    #[error("session not found: topic={0}")]
    SessionNotFound(String),

    #[error("session expired: topic={0}")]
    SessionExpired(String),

    #[error("session method not authorized: {0}")]
    MethodNotAuthorized(String),

    #[error("pairing rejected by user")]
    PairingRejected,

    #[error("relay error: {0}")]
    Relay(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("websocket error: {0}")]
    WebSocket(String),
}

impl From<hpx_yawc::WebSocketError> for WcError {
    fn from(e: hpx_yawc::WebSocketError) -> Self {
        Self::WebSocket(e.to_string())
    }
}

pub type WcResult<T> = Result<T, WcError>;
