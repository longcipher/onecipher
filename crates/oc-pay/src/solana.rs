//! `SolanaSettler` — submits Solana transactions directly to an RPC endpoint.
//!
//! Per R36 / R37, the Solana settler is simpler than the EVM settler: there is
//! no Paymaster on Solana, so the Agent itself holds SOL and pays gas. The
//! settler signs a Solana tx with the session key, submits it via the
//! [`SolanaRpcClient`] trait, and returns the resulting signature in the
//! [`PaymentReceipt`].
//!
//! # Phase 1 MVP scope
//!
//! Phase 1 ships the trait surface + a mock-friendly scaffolding. The
//! [`SolanaRpcClient`] trait abstracts the Solana JSON-RPC
//! `sendTransaction` call; real impls (`solana-client` / `solana-rpc-client`)
//! live in `oc-netagent` (T19). Signing is stubbed locally with a deterministic
//! mock signature; real Key-Agent signing is T19's job.

use async_trait::async_trait;
use rust_decimal::Decimal;

use crate::{
    error::PayError,
    settler::PaymentSettler,
    types::{Caip19Asset, ChannelId, PaymentReceipt, PaymentScheme, SessionKey},
};

/// Solana RPC client trait — abstracts `sendTransaction` / `getAccountInfo`.
///
/// Real impls (`solana-rpc-client`) live in `oc-netagent`. Phase 1 ships only
/// test mocks.
#[async_trait]
pub trait SolanaRpcClient: Send + Sync {
    /// Submit a signed Solana transaction (raw bytes) and return the base58
    /// transaction signature.
    async fn send_transaction(&self, tx: &[u8]) -> Result<String, PayError>;

    /// Fetch a Solana account's data (returns `None` if the account does not
    /// exist). Used by channel-state introspection; Phase 1 settlers do not
    /// call this.
    async fn get_account(&self, address: &str) -> Result<Option<Vec<u8>>, PayError>;
}

/// Solana payment settler — submits Solana txs directly to RPC (no Paymaster).
///
/// The settler supports only [`PaymentScheme::Exact`] on Solana (no EIP-4337
/// equivalent exists; the SCA pattern is replaced by Session Tokens — see
/// `oc-session-key`).
pub struct SolanaSettler {
    chain_id: String,
    supported: Vec<PaymentScheme>,
    rpc: Box<dyn SolanaRpcClient>,
}

impl SolanaSettler {
    /// Construct a new `SolanaSettler`.
    ///
    /// `chain_id` is a CAIP-2 string like `"solana:mainnet"` or
    /// `"solana:devnet"`. The settler supports only `Exact` on Solana.
    pub fn new(chain_id: impl Into<String>, rpc: Box<dyn SolanaRpcClient>) -> Self {
        Self { chain_id: chain_id.into(), supported: vec![PaymentScheme::Exact], rpc }
    }

    /// Build a minimal mock Solana transaction (Phase 1 stub).
    ///
    /// Real borsh-encoded instruction layout lives in `oc-netagent`. Phase 1
    /// produces a deterministic byte buffer with recipient + amount for
    /// round-trip test assertions.
    fn build_tx(recipient: &str, amount: Decimal) -> Vec<u8> {
        let mut buf = Vec::with_capacity(48 + recipient.len());
        buf.extend_from_slice(recipient.as_bytes());
        buf.extend_from_slice(amount.to_string().as_bytes());
        buf
    }

    /// Sign a Solana tx with the payer's session key (Phase 1 mock).
    ///
    /// Real signing is delegated to the Key-Agent (T19). Phase 1 appends a
    /// 64-byte mock ed25519 signature derived from the session key id.
    fn sign_tx(tx: &mut Vec<u8>, payer: &SessionKey) -> Result<(), PayError> {
        let mut sig = [0u8; 64];
        let id_bytes = payer.key_id.as_bytes();
        let n = id_bytes.len().min(64);
        sig[..n].copy_from_slice(&id_bytes[..n]);
        tx.extend_from_slice(&sig);
        Ok(())
    }

    /// Validate the payer / recipient / amount for a `pay_exact` call.
    fn validate(
        &self,
        payer: &SessionKey,
        recipient: &str,
        amount: Decimal,
    ) -> Result<(), PayError> {
        if payer.chain_id != self.chain_id {
            return Err(PayError::ChainMismatch {
                expected: self.chain_id.clone(),
                actual: payer.chain_id.clone(),
            });
        }
        if recipient.is_empty() {
            return Err(PayError::InvalidRecipient(recipient.to_string()));
        }
        if amount <= Decimal::ZERO {
            return Err(PayError::InvalidAmount);
        }
        Ok(())
    }
}

#[async_trait]
impl PaymentSettler for SolanaSettler {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    fn supported_schemes(&self) -> &[PaymentScheme] {
        &self.supported
    }

    async fn pay_exact(
        &self,
        payer: &SessionKey,
        recipient: &str,
        amount: Decimal,
        asset: Caip19Asset,
    ) -> Result<PaymentReceipt, PayError> {
        self.validate(payer, recipient, amount)?;

        let mut tx = Self::build_tx(recipient, amount);
        Self::sign_tx(&mut tx, payer)?;
        let signature = self.rpc.send_transaction(&tx).await?;

        Ok(PaymentReceipt::new(
            self.chain_id.clone(),
            PaymentScheme::Exact,
            signature,
            amount,
            asset,
            recipient,
        ))
    }

    async fn open_channel(
        &self,
        payer: &SessionKey,
        recipient: &str,
        max_amount: Decimal,
    ) -> Result<ChannelId, PayError> {
        // Phase 1 stub: Solana MPP channels route through TempoSettler. We
        // still implement open_channel so the trait is satisfied for the
        // Solana-only test path; the returned ChannelId is deterministic.
        self.validate(payer, recipient, max_amount)?;
        let mut bytes = [0u8; 32];
        let id_bytes = payer.key_id.as_bytes();
        let n = id_bytes.len().min(16);
        bytes[..n].copy_from_slice(&id_bytes[..n]);
        let r_bytes = recipient.as_bytes();
        let m = r_bytes.len().min(16);
        bytes[16..16 + m].copy_from_slice(&r_bytes[..m]);
        Ok(ChannelId::from_bytes(bytes))
    }

    async fn close_channel(&self, _channel_id: &ChannelId) -> Result<PaymentReceipt, PayError> {
        Err(PayError::TempoError(
            "SolanaSettler does not implement close_channel — use TempoSettler for MPP".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSolanaRpc {
        signature: String,
    }

    #[async_trait]
    impl SolanaRpcClient for MockSolanaRpc {
        async fn send_transaction(&self, _tx: &[u8]) -> Result<String, PayError> {
            Ok(self.signature.clone())
        }

        async fn get_account(&self, _address: &str) -> Result<Option<Vec<u8>>, PayError> {
            Ok(Some(vec![0x01]))
        }
    }

    fn dummy_session_key() -> SessionKey {
        use oc_session_key::{KeyScheme, PublicKey};
        SessionKey::new(
            PublicKey { bytes: vec![0u8; 32], scheme: KeyScheme::Ed25519Solana },
            "solana:mainnet",
            "sol-key-1",
        )
    }

    #[tokio::test]
    async fn test_solana_settler_pay_exact_mock() {
        let settler = SolanaSettler::new(
            "solana:mainnet",
            Box::new(MockSolanaRpc { signature: "sol_sig_mock".into() }),
        );
        let r = settler
            .pay_exact(
                &dummy_session_key(),
                "recipient_addr",
                Decimal::from(1),
                Caip19Asset::unchecked("solana:mainnet/slip44:501"),
            )
            .await
            .unwrap();
        assert_eq!(r.tx_hash, "sol_sig_mock");
        assert_eq!(r.scheme, PaymentScheme::Exact);
        assert_eq!(r.chain_id, "solana:mainnet");
    }

    #[tokio::test]
    async fn test_solana_settler_supported_schemes() {
        let settler = SolanaSettler::new(
            "solana:mainnet",
            Box::new(MockSolanaRpc { signature: "sol_sig_mock".into() }),
        );
        let s = settler.supported_schemes();
        assert_eq!(s, &[PaymentScheme::Exact]);
    }

    #[tokio::test]
    async fn test_solana_settler_rejects_chain_mismatch() {
        let settler = SolanaSettler::new(
            "solana:mainnet",
            Box::new(MockSolanaRpc { signature: "sol_sig_mock".into() }),
        );
        let mut sk = dummy_session_key();
        sk.chain_id = "solana:devnet".into();
        let err = settler
            .pay_exact(
                &sk,
                "recipient_addr",
                Decimal::from(1),
                Caip19Asset::unchecked("solana:mainnet/slip44:501"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PayError::ChainMismatch { .. }));
    }

    #[tokio::test]
    async fn test_solana_settler_rejects_invalid_recipient() {
        let settler = SolanaSettler::new(
            "solana:mainnet",
            Box::new(MockSolanaRpc { signature: "sol_sig_mock".into() }),
        );
        let err = settler
            .pay_exact(
                &dummy_session_key(),
                "",
                Decimal::from(1),
                Caip19Asset::unchecked("solana:mainnet/slip44:501"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PayError::InvalidRecipient(_)));
    }

    #[tokio::test]
    async fn test_solana_settler_rejects_invalid_amount() {
        let settler = SolanaSettler::new(
            "solana:mainnet",
            Box::new(MockSolanaRpc { signature: "sol_sig_mock".into() }),
        );
        let err = settler
            .pay_exact(
                &dummy_session_key(),
                "recipient_addr",
                Decimal::ZERO,
                Caip19Asset::unchecked("solana:mainnet/slip44:501"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PayError::InvalidAmount));
    }

    #[tokio::test]
    async fn test_solana_settler_close_channel_not_supported() {
        let settler = SolanaSettler::new(
            "solana:mainnet",
            Box::new(MockSolanaRpc { signature: "sol_sig_mock".into() }),
        );
        let id = ChannelId::for_test(1);
        let err = settler.close_channel(&id).await.unwrap_err();
        assert!(matches!(err, PayError::TempoError(_)));
    }
}
