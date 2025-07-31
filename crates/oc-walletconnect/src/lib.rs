//! WalletConnect v2 protocol wrapper for OneCipher.
//!
//! Provides two roles:
//! - [`wallet_server::WcWalletServer`] — used by the daemon (Network-Agent) to respond to dApp
//!   requests over the WC v2 relay.
//! - [`dapp_client::WcDappClient`] — used by the CLI to connect to a remote daemon as a dApp.
//!
//! Both roles share the same crypto + relay + JSON-RPC layers.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod dapp_client;
pub mod error;
pub mod jsonrpc;
pub mod method;
pub mod relay;
pub mod session;
pub mod uri;
pub mod wallet_server;

pub use crypto::{WcCipher, WcKeyPair, WcSharedSecret, WcSymKey};
pub use dapp_client::WcDappClient;
pub use error::{WcError, WcResult};
pub use jsonrpc::{JsonRpcError, JsonRpcErrorCode, JsonRpcRequest, JsonRpcResponse};
pub use method::{
    PERSONAL_SIGN, ProposerMetadata, SESSION_DELETE, SESSION_EVENT, SESSION_PING, SESSION_PROPOSE,
    SESSION_REQUEST, SESSION_SETTLE, SESSION_UPDATE, SessionProposeParams, SessionSettleParams,
};
pub use relay::{RelayClient, RelayConfig};
pub use session::{WcSession, WcSessionState, WcSessionTable};
pub use uri::PairingUri;
pub use wallet_server::{WalletMethodHandler, WcServerHandle, WcWalletConfig, WcWalletServer};

#[cfg(any(test, feature = "test-utils"))]
pub mod mock_relay;
