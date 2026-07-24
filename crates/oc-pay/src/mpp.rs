//! `PayMPP` — bidirectional stream RPC for MPP channel payments.
//!
//! Per R35, the MPP path is `open → stream chunks → close`. The stream is
//! bidirectional: the payer sends payment chunks (credits to the recipient)
//! and the recipient sends back acks / receipts.
//!
//! # Phase 1 MVP scope
//!
//! Phase 1 defines the types and a minimal stream handle that wraps a
//! [`crate::tempo::TempoChannelClient`]. Real bidirectional streaming over
//! gRPC / WebSocket (Tempo's wire protocol) is T19's job; Phase 1's
//! [`PayMpp`] is a stub that drives the channel client synchronously (one
//! `stream` call per chunk) and surfaces a final receipt on `close`.
//!
//! See the T18 Deviation Note in the task report.

use rust_decimal::Decimal;

use crate::{
    error::PayError,
    tempo::TempoChannelClient,
    types::{Caip19Asset, ChannelId, PaymentReceipt, PaymentScheme, SessionKey},
};

/// A single chunk payment streamed through an MPP channel.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MppChunk {
    /// Channel id this chunk is for.
    pub channel_id: ChannelId,
    /// Chunk amount (smallest on-chain unit).
    pub amount: Decimal,
    /// Optional chunk sequence number — the recipient can use this to detect
    /// gaps. Phase 1 does not enforce monotonicity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

/// Ack returned by the recipient for each chunk. Phase 1 carries the
/// cumulative streamed amount so the payer can reconcile.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MppAck {
    /// Cumulative amount streamed through the channel after this chunk.
    pub cumulative: Decimal,
}

/// Stream handle for an open MPP channel.
///
/// Phase 1 stubs the bidirectional stream: `stream_chunk` blocks on a single
/// `TempoChannelClient::stream` call. Real impls (T19) will multiplex chunks
/// over a long-lived gRPC bidi stream.
pub struct MppStreamHandle<'a> {
    client: &'a dyn TempoChannelClient,
    channel_id: ChannelId,
    payer: SessionKey,
    recipient: String,
}

impl<'a> MppStreamHandle<'a> {
    /// Construct a stream handle bound to a specific channel. The handle
    /// borrows the Tempo client so it can be cheaply constructed per
    /// open-channel call.
    pub fn new(
        client: &'a dyn TempoChannelClient,
        channel_id: ChannelId,
        payer: SessionKey,
        recipient: impl Into<String>,
    ) -> Self {
        Self { client, channel_id, payer, recipient: recipient.into() }
    }

    /// Stream a single chunk through the channel. Returns the cumulative
    /// amount streamed so far.
    pub async fn stream_chunk(&self, amount: Decimal) -> Result<MppAck, PayError> {
        if amount <= Decimal::ZERO {
            return Err(PayError::InvalidAmount);
        }
        let cumulative = self.client.stream(&self.channel_id, amount).await?;
        Ok(MppAck { cumulative })
    }

    /// Close the channel and return the final settlement receipt.
    ///
    /// Phase 1 delegates to [`TempoChannelClient::close`]; the returned
    /// receipt's `amount` is the total streamed through this handle.
    pub async fn close(self) -> Result<PaymentReceipt, PayError> {
        // We can't reuse the TempoSettler's close_channel from here (it owns
        // the client); instead we call the client directly and construct the
        // receipt.
        let (tx_hash, total_amount) = self.client.close(&self.channel_id).await?;
        Ok(PaymentReceipt::new(
            // We don't have a chain_id on the handle in Phase 1 — surface the
            // payer's chain_id so the receipt is non-empty. Real impls (T19)
            // carry the chain id on the channel record.
            self.payer.chain_id.clone(),
            // MPP close uses Exact semantics (single-shot settlement of the
            // channel balance).
            PaymentScheme::Exact,
            tx_hash,
            total_amount,
            // Asset is not known at this layer in Phase 1 — surface a
            // placeholder. Real impls track this on the channel record.
            Caip19Asset::unchecked("eip155:8453/slip44:60"),
            self.recipient,
        ))
    }
}

/// `PayMPP` — entrypoint for the MPP bidirectional stream RPC.
///
/// Phase 1 stubs the RPC: [`PayMpp::open`] returns an [`MppStreamHandle`] that
/// drives the Tempo client synchronously. Real impls (T19) will wrap a gRPC
/// bidi stream and surface [`MppChunk`] / [`MppAck`] over a tokio channel.
#[derive(Debug, Default, Clone, Copy)]
pub struct PayMpp;

impl PayMpp {
    /// Construct a new `PayMpp` RPC handle.
    pub const fn new() -> Self {
        Self
    }

    /// Open an MPP stream over an existing channel and return a handle for
    /// streaming chunks.
    #[allow(clippy::unused_async, reason = "Phase 1 stub — T19 will add real async streaming")]
    pub async fn open<'a>(
        &self,
        client: &'a dyn TempoChannelClient,
        channel_id: ChannelId,
        payer: SessionKey,
        recipient: String,
    ) -> Result<MppStreamHandle<'a>, PayError> {
        // Phase 1 stub: just construct the handle. Real impls (T19) will
        // open a gRPC bidi stream here and surface chunks/acks over a tokio
        // channel.
        Ok(MppStreamHandle::new(client, channel_id, payer, recipient))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, future::Future, pin::Pin, sync::Mutex};

    use rust_decimal::Decimal;

    use super::*;
    use crate::{tempo::TempoChannelClient, types::ChannelState};

    struct MockTempo {
        streamed: Mutex<HashMap<ChannelId, Decimal>>,
    }

    impl MockTempo {
        fn new() -> Self {
            Self { streamed: Mutex::new(HashMap::new()) }
        }
    }

    impl TempoChannelClient for MockTempo {
        fn open(
            &self,
            _payer: &SessionKey,
            _recipient: &str,
            _max_amount: Decimal,
        ) -> Pin<Box<dyn Future<Output = Result<ChannelId, PayError>> + Send + '_>> {
            unreachable!("PayMpp tests call stream/close only")
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
            let total = self
                .streamed
                .lock()
                .expect("streamed poisoned")
                .get(channel_id)
                .copied()
                .unwrap_or(Decimal::ZERO);
            let hex = channel_id.hex.clone();
            Box::pin(async move { Ok((format!("0xclose_{hex}"), total)) })
        }

        fn state(
            &self,
            _channel_id: &ChannelId,
        ) -> Pin<Box<dyn Future<Output = Result<ChannelState, PayError>> + Send + '_>> {
            Box::pin(async { Ok(ChannelState::Open) })
        }
    }

    fn dummy_session_key() -> SessionKey {
        use oc_session_key::{KeyScheme, PublicKey};
        SessionKey::new(
            PublicKey { bytes: vec![0u8; 33], scheme: KeyScheme::Secp256k1Evm },
            "eip155:8453",
            "mpp-key-1",
        )
    }

    #[tokio::test]
    async fn test_mpp_open_stream_close() {
        let client = MockTempo::new();
        let channel_id = ChannelId::for_test(1);
        let payer = dummy_session_key();
        let pay_mpp = PayMpp::new();
        let handle = pay_mpp
            .open(&client, channel_id.clone(), payer.clone(), "0xpeer".to_string())
            .await
            .unwrap();

        // Stream three chunks and verify cumulative accounting.
        let ack1 = handle.stream_chunk(Decimal::from(1)).await.unwrap();
        assert_eq!(ack1.cumulative, Decimal::from(1));
        let ack2 = handle.stream_chunk(Decimal::from(2)).await.unwrap();
        assert_eq!(ack2.cumulative, Decimal::from(3));
        let ack3 = handle.stream_chunk(Decimal::from(4)).await.unwrap();
        assert_eq!(ack3.cumulative, Decimal::from(7));

        let receipt = handle.close().await.unwrap();
        assert_eq!(receipt.amount, Decimal::from(7));
        assert!(receipt.tx_hash.starts_with("0xclose_"));
    }

    #[tokio::test]
    async fn test_mpp_rejects_zero_chunk() {
        let client = MockTempo::new();
        let channel_id = ChannelId::for_test(1);
        let payer = dummy_session_key();
        let pay_mpp = PayMpp::new();
        let handle = pay_mpp.open(&client, channel_id, payer, "0xpeer".to_string()).await.unwrap();
        let err = handle.stream_chunk(Decimal::ZERO).await.unwrap_err();
        assert!(matches!(err, PayError::InvalidAmount));
    }

    #[test]
    fn test_mpp_chunk_serde() {
        let chunk = MppChunk {
            channel_id: ChannelId::for_test(7),
            amount: Decimal::from(42),
            seq: Some(3),
        };
        let json = serde_json::to_string(&chunk).unwrap();
        let chunk2: MppChunk = serde_json::from_str(&json).unwrap();
        assert_eq!(chunk, chunk2);
    }
}
