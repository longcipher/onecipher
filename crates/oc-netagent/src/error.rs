//! `NetAgentError` — top-level error type for the Network-Agent.

use thiserror::Error;

/// Top-level error for the Network-Agent server + Key-Agent client.
#[derive(Debug, Error)]
pub enum NetAgentError {
    /// I/O error (UDS bind/connect, frame read/write).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// prost decode failure (Key-Agent response payload or wire frame).
    #[error("prost decode error: {0}")]
    ProstDecode(#[from] prost::DecodeError),
    /// Key-Agent wire protocol error (truncated frame, oversized payload, etc.).
    #[error("Key-Agent wire error: {0}")]
    KeyAgentWire(String),
    /// Key-Agent returned an `Error` response (non-policy failure).
    #[error("Key-Agent returned error: {0}")]
    KeyAgentError(String),
    /// Key-Agent returned a policy `Deny` response carrying the deny reason.
    #[error("Key-Agent policy DENY: {0:?}")]
    KeyAgentDeny(oc_keyagent::proto::DenyReason),
    /// Invalid request from the client (could not be translated to a
    /// `KeyAgentRequest` variant).
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Internal error (unreachable invariant, codec mismatch, etc.).
    #[error("internal error: {0}")]
    Internal(String),
    /// WC session store error.
    #[error("session store error: {0}")]
    SessionStore(#[from] crate::wc_session_store::SessionStoreError),
    /// WalletConnect v2 protocol error.
    #[error("walletconnect error: {0}")]
    Wc(#[from] oc_walletconnect::WcError),
}
