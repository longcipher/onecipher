// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! WalletConnect v2 protocol wrapper for OneCipher.
//!
//! Provides two roles:
//! - [`wallet_server::WcWalletServer`] — used by the daemon (Network-Agent) to respond to dApp
//!   requests over the WC v2 relay.
//! - [`dapp_client::WcDappClient`] — used by the CLI to connect to a remote daemon as a dApp.
//!
//! Both roles share the same crypto + relay + JSON-RPC layers.

#![forbid(unsafe_code)]

pub mod auth;
pub mod crypto;
pub mod dapp_client;
pub mod error;
pub mod jsonrpc;
pub mod method;
pub mod relay;
pub mod session;
pub mod uri;
pub mod wallet_server;

pub use auth::{
    AuthError, AuthRequestParams, AuthType, build_siwe_message, chain_reference, eip4361_hash,
    split_caip2,
};
pub use crypto::{WcCipher, WcKeyPair, WcSharedSecret, WcSymKey};
pub use dapp_client::WcDappClient;
pub use error::{WcError, WcResult};
pub use jsonrpc::{JsonRpcError, JsonRpcErrorCode, JsonRpcRequest, JsonRpcResponse};
pub use method::{
    AUTH_REQUEST, AUTH_RESPONSE, PERSONAL_SIGN, ProposerMetadata, SESSION_DELETE, SESSION_EVENT,
    SESSION_PING, SESSION_PROPOSE, SESSION_REQUEST, SESSION_SETTLE, SESSION_UPDATE,
    SessionProposeParams, SessionSettleParams,
};
pub use relay::{RelayClient, RelayConfig, apply_project_id};
pub use session::{WcSession, WcSessionState, WcSessionTable, WcSymKeyHex};
pub use uri::PairingUri;
pub use wallet_server::{WalletMethodHandler, WcServerHandle, WcWalletConfig, WcWalletServer};

#[cfg(any(test, feature = "test-utils"))]
pub mod mock_relay;
