//! Solana Session Key Provider — Session Tokens program.
//!
//! Per the design (§5.1), the Solana provider calls the Session Tokens program
//! to grant / verify / revoke session keys. Phase 1 uses a simplified mock
//! instruction encoding; real borsh encoding + Solana RPC lives in
//! `oc-netagent` (Phase D, R74 YAGNI). The program id is a config value (A3).

use async_trait::async_trait;
use oc_policy::PolicyV2;
use oc_signer::{chains::SolanaSigner, traits::ChainSigner};

use crate::{
    SessionKeyProvider,
    error::SessionKeyError,
    rpc::RpcClient,
    types::{
        GrantReceipt, OwnerKey, PublicKey, SessionPrivateKey, SignPayload, Signature,
        SolanaInstruction,
    },
};

/// Solana Session Key Provider — Session Tokens program.
pub struct SolanaSessionKeyProvider {
    /// CAIP-2 chain id, e.g. `"solana:mainnet"` or `"solana:devnet"`.
    pub chain_id: String,
    /// Session Tokens program id (base58), config value per A3.
    pub program_id: String,
    /// Injectable RPC client (real impls live in `oc-netagent`).
    pub rpc: Box<dyn RpcClient>,
}

impl SolanaSessionKeyProvider {
    /// Construct a new Solana session-key provider.
    pub fn new(
        chain_id: impl Into<String>,
        program_id: impl Into<String>,
        rpc: Box<dyn RpcClient>,
    ) -> Self {
        Self { chain_id: chain_id.into(), program_id: program_id.into(), rpc }
    }

    /// Encode the `CreateSessionToken` instruction.
    ///
    /// **Deviation note (R74 YAGNI):** Phase 1 uses a simplified mock encoding
    /// (1-byte discriminator + raw pubkey + length-prefixed JSON policy). Real
    /// borsh encoding lives in `oc-netagent`.
    fn encode_create_session_token_ix(
        program_id: &str,
        session_pubkey: &[u8],
        policy: &PolicyV2,
    ) -> SolanaInstruction {
        let mut data = Vec::new();
        // Instruction discriminator: CreateSessionToken = 1.
        data.push(1);
        data.extend_from_slice(session_pubkey);
        let policy_json = serde_json::to_vec(policy).unwrap_or_default();
        data.extend_from_slice(&(policy_json.len() as u32).to_le_bytes());
        data.extend_from_slice(&policy_json);
        SolanaInstruction { program_id: program_id.to_string(), accounts: vec![], data }
    }
}

#[async_trait]
impl SessionKeyProvider for SolanaSessionKeyProvider {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    async fn grant(
        &self,
        owner_key: &OwnerKey,
        session_pubkey: &PublicKey,
        policy: &PolicyV2,
    ) -> Result<GrantReceipt, SessionKeyError> {
        if owner_key.chain_id != self.chain_id {
            return Err(SessionKeyError::ChainMismatch {
                expected: self.chain_id.clone(),
                actual: owner_key.chain_id.clone(),
            });
        }
        let ix =
            Self::encode_create_session_token_ix(&self.program_id, &session_pubkey.bytes, policy);
        let sig = self.rpc.send_solana_tx(vec![ix]).await?;
        // Mock: derive a session_tokens_account from the returned signature.
        // Real derivation (PDA) lives in oc-netagent.
        Ok(GrantReceipt::Solana {
            session_tokens_account: sig,
            program_id: self.program_id.clone(),
            slot: 0,
        })
    }

    async fn verify_active(&self, session_key_id: &str) -> Result<bool, SessionKeyError> {
        let account = self.rpc.get_solana_account(session_key_id).await?;
        Ok(account.is_some())
    }

    async fn revoke(
        &self,
        owner_key: &OwnerKey,
        session_key_id: &str,
    ) -> Result<(), SessionKeyError> {
        if owner_key.chain_id != self.chain_id {
            return Err(SessionKeyError::ChainMismatch {
                expected: self.chain_id.clone(),
                actual: owner_key.chain_id.clone(),
            });
        }
        let ix = SolanaInstruction {
            program_id: self.program_id.clone(),
            accounts: vec![session_key_id.to_string()],
            // Instruction discriminator: RevokeSessionToken = 2.
            data: vec![2],
        };
        let _ = self.rpc.send_solana_tx(vec![ix]).await?;
        Ok(())
    }

    async fn sign_with(
        &self,
        session_priv: &SessionPrivateKey,
        payload: &SignPayload,
    ) -> Result<Signature, SessionKeyError> {
        // Solana uses ed25519 signing. Delegate to oc-signer's SolanaSigner
        // (ponytail ladder — reuse, don't re-roll).
        match payload {
            SignPayload::Message { bytes } => {
                let signer = SolanaSigner;
                let sig = signer
                    .sign_message(session_priv.raw.expose(), bytes)
                    .map_err(|e| SessionKeyError::SigningFailed(e.to_string()))?;
                Ok(Signature::Solana { base58: bs58::encode(&sig.signature).into_string() })
            }
            _ => Err(SessionKeyError::InvalidPayload(
                "Solana supports only Message payload in Phase 1".to_string(),
            )),
        }
    }
}
