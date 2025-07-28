//! oc-session-key — Multi-chain `SessionKeyProvider` trait + EVM/Solana impls.
//!
//! Per R21, defines the `SessionKeyProvider` trait unifying multi-chain
//! session-key grant/verify/revoke/sign. Per R56, this crate MUST NOT depend on
//! tokio / reqwest / tungstenite / hyper / async-std / smol — it uses
//! `async-trait` only, producing runtime-agnostic futures. The Net-Agent
//! supplies the runtime; the Key-Agent calls these via the Net-Agent relay.
//!
//! Phase 1 ships `EvmSessionKeyProvider` (ERC-7715 on ERC-7579 SCA) and
//! `SolanaSessionKeyProvider` (Session Tokens program) backed by a unified
//! [`rpc::MockRpcClient`]. Phase 2 (module [`real`]) adds split
//! [`real::EvmRpcClient`] + [`real::EvmBundlerClient`] + [`real::SolanaRpcClient`]
//! traits with injectable real providers — the same `SessionKeyProvider` trait
//! backed by chain-specific RPC abstractions that `oc-netagent` wires up to
//! alloy / solana-client. Real on-chain RPC calls happen in `oc-netagent`.
//!
//! # Source
//! `docs/design.md` §5.1, §6.2.

#![deny(unsafe_code)]

pub mod error;
pub mod evm;
pub mod real;
pub mod rpc;
pub mod solana;
pub mod types;

pub use async_trait::async_trait;
pub use error::SessionKeyError;
pub use evm::EvmSessionKeyProvider;
pub use oc_policy::PolicyV2;
pub use real::{EvmBundlerClient, EvmRpcClient, SolanaRpcClient, derive_session_key_id};
pub use rpc::{MockRpcClient, MockRpcCounters, RpcClient};
pub use solana::SolanaSessionKeyProvider;
pub use types::{
    GrantReceipt, KeyScheme, OwnerKey, PublicKey, SessionPrivateKey, SignPayload, Signature,
    SolanaInstruction,
};

/// The multi-chain `SessionKeyProvider` trait (R21).
///
/// Unifies session-key grant / verify / revoke / sign across chains. Phase 1
/// implementations: [`EvmSessionKeyProvider`] (ERC-7715 on ERC-7579 SCA),
/// [`SolanaSessionKeyProvider`] (Session Tokens program).
///
/// The trait is `#[async_trait]` but the futures are runtime-agnostic — the
/// caller supplies the executor (e.g. `futures::executor::block_on` in tests,
/// the Net-Agent's tokio runtime in production).
#[async_trait]
pub trait SessionKeyProvider: Send + Sync {
    /// CAIP-2 chain id, e.g. `"eip155:8453"` or `"solana:mainnet"`.
    fn chain_id(&self) -> &str;

    /// Register the session key on-chain and return a receipt (R24).
    async fn grant(
        &self,
        owner_key: &OwnerKey,
        session_pubkey: &PublicKey,
        policy: &PolicyV2,
    ) -> Result<GrantReceipt, SessionKeyError>;

    /// Verify the session key is still active on-chain (not revoked / expired).
    async fn verify_active(&self, session_key_id: &str) -> Result<bool, SessionKeyError>;

    /// Revoke the session key on-chain (signed by the owner key).
    async fn revoke(
        &self,
        owner_key: &OwnerKey,
        session_key_id: &str,
    ) -> Result<(), SessionKeyError>;

    /// Sign a payload with the session private key. Signing is local (no RPC);
    /// the SCA / on-chain program validates the signature.
    async fn sign_with(
        &self,
        session_priv: &SessionPrivateKey,
        payload: &SignPayload,
    ) -> Result<Signature, SessionKeyError>;
}

#[cfg(test)]
mod tests;
