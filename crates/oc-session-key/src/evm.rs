//! EVM Session Key Provider — ERC-7715 `grantPermission` on an ERC-7579 SCA.
//!
//! Per R24, EVM session-key permissions are registered on-chain via ERC-7715.
//! Phase 1 builds a simplified Merkle root from the `PolicyV2` (SHA-256 of the
//! serialized policy — see Deviation Note) and a simplified mock ABI encoding.
//! Real Merkle tree + ABI encoding lives in `oc-netagent` (Phase D, R74 YAGNI).

use std::{future::Future, pin::Pin};

use oc_policy::PolicyV2;
use oc_signer::{chains::EvmSigner, traits::ChainSigner};
use sha2::{Digest, Sha256};

use crate::{
    SessionKeyProvider,
    error::SessionKeyError,
    rpc::RpcClient,
    types::{GrantReceipt, OwnerKey, PublicKey, SessionPrivateKey, SignPayload, Signature},
};

/// EVM Session Key Provider — ERC-7715 `grantPermission` on an ERC-7579 SCA.
pub struct EvmSessionKeyProvider {
    /// CAIP-2 chain id, e.g. `"eip155:8453"` (Base) or `"eip155:1"` (Ethereum).
    pub chain_id: String,
    /// ERC-7579 SCA address (`0x`-prefixed).
    pub sca_address: String,
    /// Injectable RPC client (real impls live in `oc-netagent`).
    pub rpc: Box<dyn RpcClient>,
}

impl EvmSessionKeyProvider {
    /// Construct a new EVM session-key provider.
    pub fn new(
        chain_id: impl Into<String>,
        sca_address: impl Into<String>,
        rpc: Box<dyn RpcClient>,
    ) -> Self {
        Self { chain_id: chain_id.into(), sca_address: sca_address.into(), rpc }
    }

    /// Compute the ERC-7715 Merkle root from a `PolicyV2`.
    ///
    /// **Deviation note (R74 YAGNI):** Phase 1 uses SHA-256 of the serialized
    /// `PolicyV2` as a stand-in for the Merkle root. Real EVM uses keccak256 +
    /// a Merkle tree of individual permissions; that is a Phase 2 concern. The
    /// root is deterministic for a given policy, which is sufficient for the
    /// Phase 1 mock path.
    pub(crate) fn compute_merkle_root(policy: &PolicyV2) -> Result<String, SessionKeyError> {
        let json = serde_json::to_string(policy)
            .map_err(|e| SessionKeyError::MerkleFailed(e.to_string()))?;
        let hash = Sha256::digest(json.as_bytes());
        Ok(format!("0x{}", hex::encode(hash)))
    }

    /// Encode the ERC-7715 `grantPermission` calldata.
    ///
    /// **Deviation note (R74 YAGNI):** Phase 1 uses a simplified mock ABI
    /// encoding. Real ABI encoding (ethers / alloy) lives in `oc-netagent`.
    /// Selector is a placeholder; the SCA address + 32-byte args are encoded
    /// per the standard ABI layout so the mock is structurally faithful.
    fn encode_grant_permission(
        session_pubkey: &[u8],
        merkle_root: &str,
        expiry_unix: u64,
    ) -> Vec<u8> {
        const SELECTOR: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
        crate::abi::encode_grant_permission(SELECTOR, session_pubkey, merkle_root, expiry_unix)
    }

    /// Encode the `isPermissionGranted(bytes32 sessionKey)` view calldata (mock).
    fn encode_is_permission_granted(session_key_id: &str) -> Vec<u8> {
        const SELECTOR: [u8; 4] = [0xb3, 0xc4, 0xd5, 0xe6];
        crate::abi::encode_is_permission_granted(SELECTOR, session_key_id)
    }

    /// Encode the `revokePermission(bytes32 sessionKey)` calldata (mock).
    fn encode_revoke_permission(session_key_id: &str) -> Vec<u8> {
        const SELECTOR: [u8; 4] = [0xc5, 0xd6, 0xe7, 0xf8];
        crate::abi::encode_revoke_permission(SELECTOR, session_key_id)
    }
}

impl SessionKeyProvider for EvmSessionKeyProvider {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    fn grant(
        &self,
        owner_key: &OwnerKey,
        session_pubkey: &PublicKey,
        policy: &PolicyV2,
    ) -> Pin<Box<dyn Future<Output = Result<GrantReceipt, SessionKeyError>> + Send + '_>> {
        if owner_key.chain_id != self.chain_id {
            let (expected, actual) = (self.chain_id.clone(), owner_key.chain_id.clone());
            return Box::pin(async { Err(SessionKeyError::ChainMismatch { expected, actual }) });
        }
        let merkle_root = match Self::compute_merkle_root(policy) {
            Ok(r) => r,
            Err(e) => return Box::pin(async { Err(e) }),
        };
        let calldata = Self::encode_grant_permission(
            session_pubkey.bytes.as_slice(),
            &merkle_root,
            policy.rules.expiry_unix,
        );
        let sca = self.sca_address.clone();
        let rpc = &self.rpc;
        Box::pin(async move {
            let tx_hash = rpc.send_evm_tx(&sca, &calldata).await?;
            Ok(GrantReceipt::Evm { tx_hash, merkle_root, sca_address: sca })
        })
    }

    fn verify_active(
        &self,
        session_key_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, SessionKeyError>> + Send + '_>> {
        let calldata = Self::encode_is_permission_granted(session_key_id);
        let sca = self.sca_address.clone();
        let rpc = &self.rpc;
        Box::pin(async move {
            let result = rpc.call_evm_view(&sca, &calldata).await?;
            Ok(!result.is_empty() && result[0] != 0)
        })
    }

    fn revoke(
        &self,
        owner_key: &OwnerKey,
        session_key_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionKeyError>> + Send + '_>> {
        if owner_key.chain_id != self.chain_id {
            let (expected, actual) = (self.chain_id.clone(), owner_key.chain_id.clone());
            return Box::pin(async { Err(SessionKeyError::ChainMismatch { expected, actual }) });
        }
        let calldata = Self::encode_revoke_permission(session_key_id);
        let sca = self.sca_address.clone();
        let rpc = &self.rpc;
        Box::pin(async move {
            let _ = rpc.send_evm_tx(&sca, &calldata).await?;
            Ok(())
        })
    }

    fn sign_with(
        &self,
        session_priv: &SessionPrivateKey,
        payload: &SignPayload,
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SessionKeyError>> + Send + '_>> {
        let signer = EvmSigner;
        let priv_bytes = session_priv.raw.expose().to_vec();
        let result = match payload {
            SignPayload::Transaction { raw_hex, .. } => {
                let raw = hex::decode(raw_hex.trim_start_matches("0x"))
                    .map_err(|e| SessionKeyError::InvalidPayload(e.to_string()));
                match raw {
                    Ok(r) => signer
                        .sign_transaction(&priv_bytes, &r)
                        .map(|s| Signature::Evm { hex: format!("0x{}", hex::encode(&s.signature)) })
                        .map_err(|e| SessionKeyError::SigningFailed(e.to_string())),
                    Err(e) => Err(e),
                }
            }
            SignPayload::UserOp { user_op_hex, .. } => {
                let raw = hex::decode(user_op_hex.trim_start_matches("0x"))
                    .map_err(|e| SessionKeyError::InvalidPayload(e.to_string()));
                match raw {
                    Ok(r) => signer
                        .sign_transaction(&priv_bytes, &r)
                        .map(|s| Signature::Evm { hex: format!("0x{}", hex::encode(&s.signature)) })
                        .map_err(|e| SessionKeyError::SigningFailed(e.to_string())),
                    Err(e) => Err(e),
                }
            }
            SignPayload::Message { bytes } => signer
                .sign_message(&priv_bytes, bytes)
                .map(|s| Signature::Evm { hex: format!("0x{}", hex::encode(&s.signature)) })
                .map_err(|e| SessionKeyError::SigningFailed(e.to_string())),
            SignPayload::TypedData { json } => signer
                .sign_typed_data(&priv_bytes, json)
                .map(|s| Signature::Evm { hex: format!("0x{}", hex::encode(&s.signature)) })
                .map_err(|e| SessionKeyError::SigningFailed(e.to_string())),
        };
        Box::pin(async { result })
    }
}
