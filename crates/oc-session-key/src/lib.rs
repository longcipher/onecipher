// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! oc-session-key — Multi-chain `SessionKeyProvider` trait + EVM/Solana impls.
//!
//! Per R21, defines the `SessionKeyProvider` trait unifying multi-chain
//! session-key grant/verify/revoke/sign. Per R56, this crate MUST NOT depend on
//! tokio / reqwest / tungstenite / hyper / async-std / smol — it uses
//! native async trait support (edition 2024), producing runtime-agnostic
//! futures. The Net-Agent supplies the runtime; the Key-Agent calls these via
//! the Net-Agent relay.
//!
//! Phase 1 ships `EvmSessionKeyProvider` (ERC-7715 on ERC-7579 SCA) and
//! `SolanaSessionKeyProvider` (Session Tokens program) backed by a unified
//! [`rpc::MockRpcClient`]. Phase 2 (module [`mock_v1`]) adds split
//! [`mock_v1::EvmRpcClient`] + [`mock_v1::EvmBundlerClient`] + [`mock_v1::SolanaRpcClient`]
//! traits with injectable real providers — the same `SessionKeyProvider` trait
//! backed by chain-specific RPC abstractions that `oc-netagent` wires up to
//! alloy / solana-client. Real on-chain RPC calls happen in `oc-netagent`.
//!
//! # Source
//! `docs/design.md` §5.1, §6.2.

#![deny(unsafe_code)]

use std::{future::Future, pin::Pin};

pub mod abi;
pub mod error;
pub mod evm;
/// Phase 1 mock implementation — uses hardcoded selectors and non-standard
/// UserOp envelopes. NOT for production use. Real implementations will
/// live in oc-netagent behind the `real-rpc` feature.
pub mod mock_v1;
pub mod rpc;
pub mod solana;
pub mod types;

pub use error::SessionKeyError;
pub use evm::EvmSessionKeyProvider;
pub use mock_v1::{EvmBundlerClient, EvmRpcClient, SolanaRpcClient, derive_session_key_id};
pub use oc_policy::PolicyV2;
pub use rpc::{MockRpcClient, MockRpcCounters, RpcClient};
pub use solana::SolanaSessionKeyProvider;
pub use types::{
    GrantReceipt, KeyScheme, OwnerKey, PublicKey, SessionPrivateKey, SignPayload, Signature,
    SolanaInstruction,
};

/// Compute the ERC-7715 permission Merkle root from a `PolicyV2`.
///
/// keccak256 Merkle over canonical permission leaves (EVM-canonical hash).
/// Each leaf is `keccak256("<domain>:<canonical-value>")` for the
/// permission-relevant policy fields (chain/contract/asset whitelists, expiry,
/// amount caps, session/device binding); pairwise `keccak256(left || right)`
/// combines them (odd leaf duplicated) to a single 32-byte root, hex-encoded
/// as `0x…`. Deterministic per policy; shared by the EVM and mock providers
/// (M7 fix).
///
/// **Residual gap vs full ERC-7715:** a production SCA builds leaves from the
/// on-chain permission struct (validated via `alloy` in `oc-netagent`), not
/// from `PolicyV2` JSON projections. This root is consensus-compatible at the
/// hash level (keccak256 Merkle) but NOT wire-identical to a Solidity
/// `MerkleProof` tree until the `real-rpc` bridge supplies on-chain leaf
/// encodings. The lock test below pins the current root so any drift is
/// explicit.
pub(crate) fn compute_merkle_root(policy: &PolicyV2) -> Result<String, SessionKeyError> {
    use sha3::{Digest, Keccak256};

    fn leaf(domain: &str, value: &str) -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(domain.as_bytes());
        h.update(b":");
        h.update(value.as_bytes());
        h.finalize().into()
    }

    let rules = &policy.rules;
    let mut leaves = vec![
        leaf("session", &policy.session_key_id),
        leaf("device", &policy.device_id),
        leaf("expiry", &rules.expiry_unix.to_string()),
        leaf("max_single_usd", &rules.max_single_amount_usd.to_string()),
        leaf("max_daily_usd", &rules.max_daily_amount_usd.to_string()),
        leaf("max_monthly_usd", &rules.max_monthly_amount_usd.to_string()),
        leaf("chains", &rules.chain_whitelist.join(",")),
        leaf("contracts", &rules.contract_whitelist.join(",")),
        leaf("assets", &rules.asset_whitelist.join(",")),
        leaf(
            "budget",
            &format!("{}@{}", rules.expiry_unix, policy.budget_allocation.allocated_usd),
        ),
    ];
    // Canonical order: sort leaf hashes so field insertion order cannot fork
    // the root.
    leaves.sort_unstable();
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        let mut i = 0;
        while i < leaves.len() {
            let left = leaves[i];
            let right = if i + 1 < leaves.len() { leaves[i + 1] } else { left };
            let mut h = Keccak256::new();
            h.update(left);
            h.update(right);
            next.push(h.finalize().into());
            i += 2;
        }
        next.sort_unstable();
        leaves = next;
    }
    let root: [u8; 32] = leaves
        .into_iter()
        .next()
        .ok_or_else(|| SessionKeyError::MerkleFailed("empty permission set".to_string()))?;
    Ok(format!("0x{}", hex::encode(root)))
}

/// The multi-chain `SessionKeyProvider` trait (R21).
///
/// Unifies session-key grant / verify / revoke / sign across chains. Phase 1
/// implementations: [`EvmSessionKeyProvider`] (ERC-7715 on ERC-7579 SCA),
/// [`SolanaSessionKeyProvider`] (Session Tokens program).
///
/// The trait uses native async fn (edition 2024) with runtime-agnostic
/// futures — the caller supplies the executor (e.g. `futures::executor::block_on`
/// in tests, the Net-Agent's tokio runtime in production).
pub trait SessionKeyProvider: Send + Sync {
    /// CAIP-2 chain id, e.g. `"eip155:8453"` or `"solana:mainnet"`.
    fn chain_id(&self) -> &str;

    /// Register the session key on-chain and return a receipt (R24).
    fn grant(
        &self,
        owner_key: &OwnerKey,
        session_pubkey: &PublicKey,
        policy: &PolicyV2,
    ) -> Pin<Box<dyn Future<Output = Result<GrantReceipt, SessionKeyError>> + Send + '_>>;

    /// Verify the session key is still active on-chain (not revoked / expired).
    fn verify_active(
        &self,
        session_key_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, SessionKeyError>> + Send + '_>>;

    /// Revoke the session key on-chain (signed by the owner key).
    fn revoke(
        &self,
        owner_key: &OwnerKey,
        session_key_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionKeyError>> + Send + '_>>;

    /// Sign a payload with the session private key. Signing is local (no RPC);
    /// the SCA / on-chain program validates the signature.
    fn sign_with(
        &self,
        session_priv: &SessionPrivateKey,
        payload: &SignPayload,
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SessionKeyError>> + Send + '_>>;
}

#[cfg(test)]
mod tests;
