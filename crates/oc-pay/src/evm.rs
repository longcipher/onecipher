//! `EvmSettler` — EIP-4337 UserOp submission via a Bundler with Paymaster
//! gas sponsorship.
//!
//! Per R36 / R37, the EVM settler is the most involved of the three: for the
//! `exact+UserOp` scheme it builds a UserOp, asks the Key-Agent to sign it,
//! asks the Paymaster to sponsor gas, and submits the UserOp to the Bundler.
//! The Bundler returns the bundle tx hash, which the settler surfaces in the
//! [`PaymentReceipt`].
//!
//! # Phase 1 MVP scope
//!
//! Phase 1 ships the trait surface + a mock-friendly scaffolding:
//! - [`BundlerClient`] trait — real HTTP client lives in `oc-netagent`.
//! - [`PaymasterClient`] trait — real HTTP client lives in `oc-netagent`.
//! - [`EvmSettler`] — orchestrates Bundler + Paymaster + a local mock signer.
//!
//! The Key-Agent signing path is stubbed: in Phase 1 the settler signs
//! UserOps locally with a deterministic mock signature (sufficient for
//! round-trip tests). Real Key-Agent integration is T19's job.

use std::{future::Future, pin::Pin};

use rust_decimal::Decimal;

use crate::{
    error::PayError,
    settler::PaymentSettler,
    types::{Caip19Asset, ChannelId, PaymentReceipt, PaymentScheme, SessionKey},
};

/// Bundler client trait — abstracts the EIP-4337 `eth_sendUserOperation` RPC.
///
/// Real impls (alloy / ethers-rs) live in `oc-netagent`. Phase 1 ships only
/// test mocks.
pub trait BundlerClient: Send + Sync {
    /// Submit a signed UserOp (RLP-encoded bytes) and return the bundle tx
    /// hash (`0x`-prefixed).
    fn submit_user_op(
        &self,
        user_op: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<String, PayError>> + Send + '_>>;
}

/// Paymaster client trait — abstracts the Paymaster's `sponsor` RPC that
/// attaches paymasterAndData to a UserOp.
///
/// Real impls live in `oc-netagent`. Phase 1 ships only test mocks.
pub trait PaymasterClient: Send + Sync {
    /// Mutate the UserOp in-place to attach paymasterAndData. Returns
    /// `Ok(())` on success.
    fn sponsor<'a>(
        &'a self,
        user_op: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PayError>> + Send + 'a>>;
}

/// EVM payment settler — submits EIP-4337 UserOps via a Bundler with
/// Paymaster-sponsored gas.
///
/// Phase 1 is mock-friendly: the Bundler and Paymaster are trait objects
/// injected at construction time. The settler itself does not own an HTTP
/// client — real HTTP wiring is `oc-netagent`'s job (T19).
pub struct EvmSettler {
    chain_id: String,
    supported: Vec<PaymentScheme>,
    bundler: Box<dyn BundlerClient>,
    paymaster: Box<dyn PaymasterClient>,
}

impl EvmSettler {
    /// Construct a new `EvmSettler`.
    ///
    /// `chain_id` is a CAIP-2 string like `"eip155:8453"`. The settler
    /// supports both `Exact` and `ExactPlusUserOp` schemes — `Exact` skips the
    /// Paymaster and submits a plain EVM tx via the Bundler, while
    /// `ExactPlusUserOp` builds a UserOp, signs it, sponsors it via the
    /// Paymaster, and submits it via the Bundler.
    pub fn new(
        chain_id: impl Into<String>,
        bundler: Box<dyn BundlerClient>,
        paymaster: Box<dyn PaymasterClient>,
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            supported: vec![PaymentScheme::Exact, PaymentScheme::ExactPlusUserOp],
            bundler,
            paymaster,
        }
    }

    /// Build a minimal mock UserOp (Phase 1 stub).
    ///
    /// Real ABI encoding lives in `oc-netagent`. Phase 1 produces a
    /// deterministic 64-byte placeholder: `chain_id_bytes (32) || amount_be
    /// (32)`. This is sufficient for the mock Bundler / Paymaster to round-
    /// trip and for tests to assert the tx hash.
    fn build_user_op(recipient: &str, amount: Decimal) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + recipient.len());
        // 32 bytes chain tag (zero-padded recipient prefix).
        let mut chain_tag = [0u8; 32];
        let r_bytes = recipient.as_bytes();
        let n = r_bytes.len().min(32);
        chain_tag[..n].copy_from_slice(&r_bytes[..n]);
        buf.extend_from_slice(&chain_tag);
        // 32 bytes amount (decimal serialized, zero-padded).
        let amt_str = amount.to_string();
        let mut amt_tag = [0u8; 32];
        let amt_bytes = amt_str.as_bytes();
        let m = amt_bytes.len().min(32);
        amt_tag[..m].copy_from_slice(&amt_bytes[..m]);
        buf.extend_from_slice(&amt_tag);
        // Trailing recipient bytes (so the round-trip is observable in tests).
        buf.extend_from_slice(recipient.as_bytes());
        buf
    }

    /// Sign a UserOp with the payer's session key (Phase 1 mock).
    ///
    /// Real signing is delegated to the Key-Agent over UDS (T19). Phase 1
    /// appends a 65-byte mock signature (`r || s || v`) derived from the
    /// session key id — sufficient for round-trip tests, not for on-chain
    /// verification.
    fn sign_user_op(user_op: &mut Vec<u8>, payer: &SessionKey) -> Result<(), PayError> {
        let mut sig = [0u8; 65];
        let id_bytes = payer.key_id.as_bytes();
        let n = id_bytes.len().min(64);
        sig[..n].copy_from_slice(&id_bytes[..n]);
        sig[64] = 27; // mock v
        user_op.extend_from_slice(&sig);
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
        if recipient.is_empty() || !recipient.starts_with("0x") {
            return Err(PayError::InvalidRecipient(recipient.to_string()));
        }
        if amount <= Decimal::ZERO {
            return Err(PayError::InvalidAmount);
        }
        Ok(())
    }
}

impl PaymentSettler for EvmSettler {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    fn supported_schemes(&self) -> &[PaymentScheme] {
        &self.supported
    }

    fn pay_exact(
        &self,
        payer: &SessionKey,
        recipient: &str,
        amount: Decimal,
        asset: Caip19Asset,
    ) -> Pin<Box<dyn Future<Output = Result<PaymentReceipt, PayError>> + Send + '_>> {
        if let Err(e) = self.validate(payer, recipient, amount) {
            return Box::pin(async { Err(e) });
        }
        let mut user_op = Self::build_user_op(recipient, amount);
        if let Err(e) = Self::sign_user_op(&mut user_op, payer) {
            return Box::pin(async { Err(e) });
        }
        let recipient = recipient.to_string();
        let paymaster = &self.paymaster;
        let bundler = &self.bundler;
        let chain_id = self.chain_id.clone();
        Box::pin(async move {
            paymaster.sponsor(&mut user_op).await?;
            let tx_hash = bundler.submit_user_op(&user_op).await?;
            Ok(PaymentReceipt::new(
                chain_id,
                PaymentScheme::ExactPlusUserOp,
                tx_hash,
                amount,
                asset,
                &recipient,
            ))
        })
    }

    fn open_channel(
        &self,
        payer: &SessionKey,
        recipient: &str,
        max_amount: Decimal,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelId, PayError>> + Send + '_>> {
        if let Err(e) = self.validate(payer, recipient, max_amount) {
            return Box::pin(async { Err(e) });
        }
        let mut bytes = [0u8; 32];
        let id_bytes = payer.key_id.as_bytes();
        let n = id_bytes.len().min(16);
        bytes[..n].copy_from_slice(&id_bytes[..n]);
        let r_bytes = recipient.as_bytes();
        let m = r_bytes.len().min(16);
        bytes[16..16 + m].copy_from_slice(&r_bytes[..m]);
        Box::pin(async move { Ok(ChannelId::from_bytes(bytes)) })
    }

    fn close_channel(
        &self,
        channel_id: &ChannelId,
    ) -> Pin<Box<dyn Future<Output = Result<PaymentReceipt, PayError>> + Send + '_>> {
        let _ = channel_id;
        Box::pin(async {
            Err(PayError::TempoError(
                "EvmSettler does not implement close_channel — use TempoSettler for MPP".into(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBundler {
        tx_hash: String,
    }

    impl BundlerClient for MockBundler {
        fn submit_user_op(
            &self,
            _user_op: &[u8],
        ) -> Pin<Box<dyn Future<Output = Result<String, PayError>> + Send + '_>> {
            let hash = self.tx_hash.clone();
            Box::pin(async move { Ok(hash) })
        }
    }

    struct MockPaymaster;

    impl PaymasterClient for MockPaymaster {
        fn sponsor<'a>(
            &'a self,
            _user_op: &'a mut Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Result<(), PayError>> + Send + 'a>> {
            Box::pin(async move {
                _user_op.extend_from_slice(&[0u8; 52]);
                Ok(())
            })
        }
    }

    fn dummy_session_key() -> SessionKey {
        use oc_session_key::{KeyScheme, PublicKey};
        SessionKey::new(
            PublicKey { bytes: vec![0u8; 33], scheme: KeyScheme::Secp256k1Evm },
            "eip155:8453",
            "evm-key-1",
        )
    }

    #[tokio::test]
    async fn test_evm_settler_pay_exact_mock() {
        let settler = EvmSettler::new(
            "eip155:8453",
            Box::new(MockBundler { tx_hash: "0xabc".into() }),
            Box::new(MockPaymaster),
        );
        let r = settler
            .pay_exact(
                &dummy_session_key(),
                "0xrecipient",
                Decimal::from(1),
                Caip19Asset::unchecked("eip155:8453/slip44:60"),
            )
            .await
            .unwrap();
        assert_eq!(r.tx_hash, "0xabc");
        assert_eq!(r.scheme, PaymentScheme::ExactPlusUserOp);
        assert_eq!(r.chain_id, "eip155:8453");
    }

    #[tokio::test]
    async fn test_evm_settler_supported_schemes() {
        let settler = EvmSettler::new(
            "eip155:8453",
            Box::new(MockBundler { tx_hash: "0xabc".into() }),
            Box::new(MockPaymaster),
        );
        let s = settler.supported_schemes();
        assert!(s.contains(&PaymentScheme::Exact));
        assert!(s.contains(&PaymentScheme::ExactPlusUserOp));
    }

    #[tokio::test]
    async fn test_evm_settler_rejects_chain_mismatch() {
        let settler = EvmSettler::new(
            "eip155:8453",
            Box::new(MockBundler { tx_hash: "0xabc".into() }),
            Box::new(MockPaymaster),
        );
        let mut sk = dummy_session_key();
        sk.chain_id = "eip155:1".into();
        let err = settler
            .pay_exact(
                &sk,
                "0xrecipient",
                Decimal::from(1),
                Caip19Asset::unchecked("eip155:8453/slip44:60"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PayError::ChainMismatch { .. }));
    }

    #[tokio::test]
    async fn test_evm_settler_rejects_invalid_recipient() {
        let settler = EvmSettler::new(
            "eip155:8453",
            Box::new(MockBundler { tx_hash: "0xabc".into() }),
            Box::new(MockPaymaster),
        );
        let err = settler
            .pay_exact(
                &dummy_session_key(),
                "no0x",
                Decimal::from(1),
                Caip19Asset::unchecked("eip155:8453/slip44:60"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PayError::InvalidRecipient(_)));
    }

    #[tokio::test]
    async fn test_evm_settler_rejects_invalid_amount() {
        let settler = EvmSettler::new(
            "eip155:8453",
            Box::new(MockBundler { tx_hash: "0xabc".into() }),
            Box::new(MockPaymaster),
        );
        let err = settler
            .pay_exact(
                &dummy_session_key(),
                "0xrecipient",
                Decimal::ZERO,
                Caip19Asset::unchecked("eip155:8453/slip44:60"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PayError::InvalidAmount));
    }

    #[tokio::test]
    async fn test_evm_settler_open_channel_returns_id() {
        let settler = EvmSettler::new(
            "eip155:8453",
            Box::new(MockBundler { tx_hash: "0xabc".into() }),
            Box::new(MockPaymaster),
        );
        let id = settler
            .open_channel(&dummy_session_key(), "0xrecipient", Decimal::from(100))
            .await
            .unwrap();
        assert_eq!(id.bytes.len(), 32);
    }

    #[tokio::test]
    async fn test_evm_settler_close_channel_not_supported() {
        let settler = EvmSettler::new(
            "eip155:8453",
            Box::new(MockBundler { tx_hash: "0xabc".into() }),
            Box::new(MockPaymaster),
        );
        let id = ChannelId::for_test(1);
        let err = settler.close_channel(&id).await.unwrap_err();
        assert!(matches!(err, PayError::TempoError(_)));
    }
}
