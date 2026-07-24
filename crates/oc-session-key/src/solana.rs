//! Solana Session Key Provider — Session Tokens program.
//!
//! Per the design (§5.1), the Solana provider calls the Session Tokens program
//! to grant / verify / revoke session keys. Phase 1 uses a simplified mock
//! instruction encoding; real borsh encoding + Solana RPC lives in
//! `oc-netagent` (Phase D, R74 YAGNI). The program id is a config value (A3).

use std::{future::Future, pin::Pin};

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

impl SessionKeyProvider for SolanaSessionKeyProvider {
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
        let ix =
            Self::encode_create_session_token_ix(&self.program_id, &session_pubkey.bytes, policy);
        let rpc = &self.rpc;
        let program_id = self.program_id.clone();
        Box::pin(async move {
            let sig = rpc.send_solana_tx(vec![ix]).await?;
            Ok(GrantReceipt::Solana { session_tokens_account: sig, program_id, slot: 0 })
        })
    }

    fn verify_active(
        &self,
        session_key_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, SessionKeyError>> + Send + '_>> {
        let rpc = &self.rpc;
        let id = session_key_id.to_string();
        Box::pin(async move {
            let account = rpc.get_solana_account(&id).await?;
            Ok(account.is_some())
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
        let ix = SolanaInstruction {
            program_id: self.program_id.clone(),
            accounts: vec![session_key_id.to_string()],
            data: vec![2],
        };
        let rpc = &self.rpc;
        Box::pin(async move {
            let _ = rpc.send_solana_tx(vec![ix]).await?;
            Ok(())
        })
    }

    fn sign_with(
        &self,
        session_priv: &SessionPrivateKey,
        payload: &SignPayload,
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SessionKeyError>> + Send + '_>> {
        match payload {
            SignPayload::Message { bytes } => {
                let signer = SolanaSigner;
                let priv_bytes = session_priv.raw.expose().to_vec();
                let bytes = bytes.clone();
                Box::pin(async move {
                    let sig = signer
                        .sign_message(&priv_bytes, &bytes)
                        .map_err(|e| SessionKeyError::SigningFailed(e.to_string()))?;
                    Ok(Signature::Solana { base58: bs58::encode(&sig.signature).into_string() })
                })
            }
            _ => Box::pin(async {
                Err(SessionKeyError::InvalidPayload(
                    "Solana supports only Message payload in Phase 1".to_string(),
                ))
            }),
        }
    }
}
