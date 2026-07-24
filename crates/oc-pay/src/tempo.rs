//! `TempoSettler` — opens / streams / closes Tempo MPP channels.
//!
//! Per R35 / R36 / R37, the Tempo settler owns the MPP channel lifecycle:
//! - `open_channel` creates a Tempo channel capped at `max_amount`.
//! - `close_channel` settles the channel on-chain and returns the final receipt.
//! - mid-life streaming is handled by [`crate::mpp::PayMpp`].
//!
//! # Phase 1 MVP scope
//!
//! Phase 1 ships the trait surface + a mock-friendly scaffolding. The
//! [`TempoChannelClient`] trait abstracts Tempo's channel RPC; real impls
//! live in `oc-netagent` (T19). On-chain settlement is stubbed (the mock
//! returns a deterministic tx hash).

use std::{collections::HashMap, future::Future, pin::Pin, sync::Mutex};

use rust_decimal::Decimal;

use crate::{
    error::PayError,
    settler::PaymentSettler,
    types::{Caip19Asset, ChannelId, ChannelState, PaymentReceipt, PaymentScheme, SessionKey},
};

/// Tempo channel client trait — abstracts Tempo's open / stream / close /
/// settle RPCs.
///
/// Real impls (HTTP client against the Tempo node) live in `oc-netagent`.
/// Phase 1 ships only test mocks.
pub trait TempoChannelClient: Send + Sync {
    /// Open a new Tempo channel capped at `max_amount` (smallest on-chain
    /// unit) and return the new channel id.
    fn open(
        &self,
        payer: &SessionKey,
        recipient: &str,
        max_amount: Decimal,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelId, PayError>> + Send + '_>>;

    /// Stream a single chunk payment of `amount` through an open channel.
    /// Returns the cumulative amount streamed so far.
    fn stream(
        &self,
        channel_id: &ChannelId,
        amount: Decimal,
    ) -> Pin<Box<dyn Future<Output = Result<Decimal, PayError>> + Send + '_>>;

    /// Close a channel and settle on-chain. Returns the final settlement tx
    /// hash and the total streamed amount.
    fn close(
        &self,
        channel_id: &ChannelId,
    ) -> Pin<Box<dyn Future<Output = Result<(String, Decimal), PayError>> + Send + '_>>;

    /// Look up a channel's current state. Used by `close_channel` to return
    /// [`PayError::ChannelClosed`] for already-closed channels.
    fn state(
        &self,
        channel_id: &ChannelId,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, PayError>> + Send + '_>>;
}

/// Tempo payment settler — owns the MPP channel lifecycle.
///
/// Phase 1 is mock-friendly: the Tempo client is a trait object injected at
/// construction time. The settler itself does not own an HTTP client.
pub struct TempoSettler {
    chain_id: String,
    supported: Vec<PaymentScheme>,
    client: Box<dyn TempoChannelClient>,
    /// In-memory record of channels this settler has opened (for the
    /// `pay_exact`-via-MPP path). Phase 1 keeps this in-process; real
    /// state lives on-chain.
    opened: Mutex<HashMap<ChannelId, Caip19Asset>>,
}

impl TempoSettler {
    /// Construct a new `TempoSettler`.
    ///
    /// `chain_id` is the CAIP-2 chain id on which Tempo channels settle
    /// (typically `eip155:8453` for Base). The settler supports no x402
    /// schemes directly — it is MPP-only — so [`PaymentSettler::pay_exact`]
    /// always returns [`PayError::InvalidRecipient`].
    pub fn new(chain_id: impl Into<String>, client: Box<dyn TempoChannelClient>) -> Self {
        Self {
            chain_id: chain_id.into(),
            supported: vec![],
            client,
            opened: Mutex::new(HashMap::new()),
        }
    }

    /// Validate that the payer / recipient / amount are well-formed.
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

impl PaymentSettler for TempoSettler {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    fn supported_schemes(&self) -> &[PaymentScheme] {
        &self.supported
    }

    fn pay_exact(
        &self,
        _payer: &SessionKey,
        _recipient: &str,
        _amount: Decimal,
        _asset: Caip19Asset,
    ) -> Pin<Box<dyn Future<Output = Result<PaymentReceipt, PayError>> + Send + '_>> {
        Box::pin(async {
            Err(PayError::TempoError(
                "TempoSettler is MPP-only — use EvmSettler / SolanaSettler for pay_exact".into(),
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
        let payer = payer.clone();
        let recipient = recipient.to_string();
        let client = &self.client;
        let opened = &self.opened;
        Box::pin(async move {
            let id = client.open(&payer, &recipient, max_amount).await?;
            opened
                .lock()
                .expect("opened mutex poisoned")
                .insert(id.clone(), Caip19Asset::unchecked("eip155:8453/slip44:60"));
            Ok(id)
        })
    }

    fn close_channel(
        &self,
        channel_id: &ChannelId,
    ) -> Pin<Box<dyn Future<Output = Result<PaymentReceipt, PayError>> + Send + '_>> {
        let client = &self.client;
        let opened = &self.opened;
        let chain_id = self.chain_id.clone();
        let channel_id = channel_id.clone();
        Box::pin(async move {
            let state = client.state(&channel_id).await?;
            match state {
                ChannelState::Closed => {
                    return Err(PayError::ChannelClosed(channel_id.hex.clone()));
                }
                ChannelState::Open => {}
            }

            let (tx_hash, total_amount) = client.close(&channel_id).await?;

            let asset = opened
                .lock()
                .expect("opened mutex poisoned")
                .remove(&channel_id)
                .unwrap_or_else(|| Caip19Asset::unchecked("eip155:8453/slip44:60"));

            Ok(PaymentReceipt::new(
                chain_id,
                PaymentScheme::Exact,
                tx_hash,
                total_amount,
                asset,
                "tempo:peer",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock Tempo client that records calls and returns configurable responses.
    struct MockTempo {
        next_id: Mutex<u64>,
        states: Mutex<HashMap<ChannelId, ChannelState>>,
        streamed: Mutex<HashMap<ChannelId, Decimal>>,
    }

    impl MockTempo {
        fn new() -> Self {
            Self {
                next_id: Mutex::new(1),
                states: Mutex::new(HashMap::new()),
                streamed: Mutex::new(HashMap::new()),
            }
        }
    }

    impl TempoChannelClient for MockTempo {
        fn open(
            &self,
            _payer: &SessionKey,
            _recipient: &str,
            _max_amount: Decimal,
        ) -> Pin<Box<dyn Future<Output = Result<ChannelId, PayError>> + Send + '_>> {
            let mut next = self.next_id.lock().expect("next_id poisoned");
            let id = ChannelId::for_test(*next);
            *next += 1;
            self.states.lock().expect("states poisoned").insert(id.clone(), ChannelState::Open);
            self.streamed.lock().expect("streamed poisoned").insert(id.clone(), Decimal::ZERO);
            Box::pin(async { Ok(id) })
        }

        fn stream(
            &self,
            channel_id: &ChannelId,
            amount: Decimal,
        ) -> Pin<Box<dyn Future<Output = Result<Decimal, PayError>> + Send + '_>> {
            let mut streamed = self.streamed.lock().expect("streamed poisoned");
            let entry = streamed.entry(channel_id.clone()).or_insert(Decimal::ZERO);
            *entry += amount;
            let result = *entry;
            Box::pin(async move { Ok(result) })
        }

        fn close(
            &self,
            channel_id: &ChannelId,
        ) -> Pin<Box<dyn Future<Output = Result<(String, Decimal), PayError>> + Send + '_>>
        {
            let mut states = self.states.lock().expect("states poisoned");
            let state = states
                .get(channel_id)
                .copied()
                .ok_or_else(|| PayError::ChannelNotFound(channel_id.hex.clone()));
            let hex = channel_id.hex.clone();
            match state {
                Ok(ChannelState::Closed) => {
                    return Box::pin(async move { Err(PayError::ChannelClosed(hex)) });
                }
                Err(e) => return Box::pin(async { Err(e) }),
                _ => {}
            }
            states.insert(channel_id.clone(), ChannelState::Closed);
            let total = self
                .streamed
                .lock()
                .expect("streamed poisoned")
                .get(channel_id)
                .copied()
                .unwrap_or(Decimal::ZERO);
            Box::pin(async move { Ok((format!("0xclose_{hex}"), total)) })
        }

        fn state(
            &self,
            channel_id: &ChannelId,
        ) -> Pin<Box<dyn Future<Output = Result<ChannelState, PayError>> + Send + '_>> {
            let states = self.states.lock().expect("states poisoned");
            let result = states
                .get(channel_id)
                .copied()
                .ok_or_else(|| PayError::ChannelNotFound(channel_id.hex.clone()));
            Box::pin(async move { result })
        }
    }

    fn dummy_session_key() -> SessionKey {
        use oc_session_key::{KeyScheme, PublicKey};
        SessionKey::new(
            PublicKey { bytes: vec![0u8; 33], scheme: KeyScheme::Secp256k1Evm },
            "eip155:8453",
            "tempo-key-1",
        )
    }

    #[tokio::test]
    async fn test_tempo_settler_open_close() {
        let settler = TempoSettler::new("eip155:8453", Box::new(MockTempo::new()));
        let id =
            settler.open_channel(&dummy_session_key(), "0xpeer", Decimal::from(100)).await.unwrap();
        assert_eq!(id.bytes.len(), 32);
        let receipt = settler.close_channel(&id).await.unwrap();
        assert!(receipt.tx_hash.starts_with("0xclose_"));
        assert_eq!(receipt.amount, Decimal::ZERO); // no streams in this test
        assert_eq!(receipt.chain_id, "eip155:8453");
    }

    #[tokio::test]
    async fn test_tempo_settler_supported_schemes_empty() {
        let settler = TempoSettler::new("eip155:8453", Box::new(MockTempo::new()));
        assert!(settler.supported_schemes().is_empty());
    }

    #[tokio::test]
    async fn test_tempo_settler_pay_exact_rejected() {
        let settler = TempoSettler::new("eip155:8453", Box::new(MockTempo::new()));
        let err = settler
            .pay_exact(
                &dummy_session_key(),
                "0xpeer",
                Decimal::from(1),
                Caip19Asset::unchecked("eip155:8453/slip44:60"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PayError::TempoError(_)));
    }

    #[tokio::test]
    async fn test_tempo_settler_close_unknown_channel() {
        let settler = TempoSettler::new("eip155:8453", Box::new(MockTempo::new()));
        let id = ChannelId::for_test(999);
        let err = settler.close_channel(&id).await.unwrap_err();
        assert!(matches!(err, PayError::ChannelNotFound(_)));
    }

    #[tokio::test]
    async fn test_tempo_settler_close_already_closed() {
        let settler = TempoSettler::new("eip155:8453", Box::new(MockTempo::new()));
        let id =
            settler.open_channel(&dummy_session_key(), "0xpeer", Decimal::from(100)).await.unwrap();
        settler.close_channel(&id).await.unwrap();
        let err = settler.close_channel(&id).await.unwrap_err();
        assert!(matches!(err, PayError::ChannelClosed(_)));
    }
}
