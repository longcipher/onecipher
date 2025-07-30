//! Integration tests for `oc-pay` settlers with mock Bundler / Paymaster /
//! Solana RPC / Tempo clients.
//!
//! These mirror the contract surface required by the T18 spec — they exercise
//! the `PaymentSettler` trait end-to-end with mockable trait-object clients
//! and assert the receipts / errors match the spec.

use std::{collections::HashMap, sync::Mutex};

use async_trait::async_trait;
use oc_pay::{
    BundlerClient, Caip19Asset, ChannelId, EvmSettler, PayError, PayMpp, PaymasterClient,
    PaymentScheme, PaymentSettler, SessionKey, SolanaRpcClient, SolanaSettler, TempoChannelClient,
    TempoSettler,
};
use oc_session_key::{KeyScheme, PublicKey};
use rust_decimal::Decimal;

// ---------------------------------------------------------------------------
// Mock clients
// ---------------------------------------------------------------------------

struct MockBundler {
    tx_hash: String,
}

#[async_trait]
impl BundlerClient for MockBundler {
    async fn submit_user_op(&self, _user_op: &[u8]) -> Result<String, PayError> {
        Ok(self.tx_hash.clone())
    }
}

struct MockPaymaster {
    fail: bool,
}

#[async_trait]
impl PaymasterClient for MockPaymaster {
    async fn sponsor(&self, _user_op: &mut Vec<u8>) -> Result<(), PayError> {
        if self.fail {
            return Err(PayError::PaymasterError("sponsor refused".into()));
        }
        _user_op.extend_from_slice(&[0u8; 52]);
        Ok(())
    }
}

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

struct MockTempo {
    next_id: Mutex<u64>,
    states: Mutex<HashMap<ChannelId, oc_pay::ChannelState>>,
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

#[async_trait]
impl TempoChannelClient for MockTempo {
    async fn open(
        &self,
        _payer: &SessionKey,
        _recipient: &str,
        _max_amount: Decimal,
    ) -> Result<ChannelId, PayError> {
        let mut next = self.next_id.lock().expect("next_id poisoned");
        let id = ChannelId::for_test(*next);
        *next += 1;
        self.states.lock().expect("states poisoned").insert(id.clone(), oc_pay::ChannelState::Open);
        self.streamed.lock().expect("streamed poisoned").insert(id.clone(), Decimal::ZERO);
        Ok(id)
    }

    async fn stream(&self, channel_id: &ChannelId, amount: Decimal) -> Result<Decimal, PayError> {
        let mut streamed = self.streamed.lock().expect("streamed poisoned");
        let entry = streamed.entry(channel_id.clone()).or_insert(Decimal::ZERO);
        *entry += amount;
        Ok(*entry)
    }

    async fn close(&self, channel_id: &ChannelId) -> Result<(String, Decimal), PayError> {
        let mut states = self.states.lock().expect("states poisoned");
        let state = states
            .get(channel_id)
            .copied()
            .ok_or_else(|| PayError::ChannelNotFound(channel_id.hex.clone()))?;
        if state == oc_pay::ChannelState::Closed {
            return Err(PayError::ChannelClosed(channel_id.hex.clone()));
        }
        states.insert(channel_id.clone(), oc_pay::ChannelState::Closed);
        let total = self
            .streamed
            .lock()
            .expect("streamed poisoned")
            .get(channel_id)
            .copied()
            .unwrap_or(Decimal::ZERO);
        Ok((format!("0xclose_{}", channel_id.hex), total))
    }

    async fn state(&self, channel_id: &ChannelId) -> Result<oc_pay::ChannelState, PayError> {
        let states = self.states.lock().expect("states poisoned");
        states
            .get(channel_id)
            .copied()
            .ok_or_else(|| PayError::ChannelNotFound(channel_id.hex.clone()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn evm_session_key() -> SessionKey {
    SessionKey::new(
        PublicKey { bytes: vec![0u8; 33], scheme: KeyScheme::Secp256k1Evm },
        "eip155:8453",
        "evm-key-1",
    )
}

fn solana_session_key() -> SessionKey {
    SessionKey::new(
        PublicKey { bytes: vec![0u8; 32], scheme: KeyScheme::Ed25519Solana },
        "solana:mainnet",
        "sol-key-1",
    )
}

// ---------------------------------------------------------------------------
// Tests required by the T18 spec
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_evm_settler_pay_exact_mock() {
    // Mock Bundler returns "0xabc..." tx_hash; mock Paymaster sponsors; assert
    // receipt.tx_hash == "0xabc...".
    let settler = EvmSettler::new(
        "eip155:8453",
        Box::new(MockBundler { tx_hash: "0xabc".into() }),
        Box::new(MockPaymaster { fail: false }),
    );
    let receipt = settler
        .pay_exact(
            &evm_session_key(),
            "0xrecipient",
            Decimal::from(1),
            Caip19Asset::unchecked("eip155:8453/slip44:60"),
        )
        .await
        .expect("evm pay_exact should succeed");
    assert_eq!(receipt.tx_hash, "0xabc");
    assert_eq!(receipt.scheme, PaymentScheme::ExactPlusUserOp);
    assert_eq!(receipt.chain_id, "eip155:8453");
    assert_eq!(receipt.amount, Decimal::from(1));
}

#[tokio::test]
async fn test_solana_settler_pay_exact_mock() {
    // Mock Solana RPC returns signature; assert receipt matches.
    let settler = SolanaSettler::new(
        "solana:mainnet",
        Box::new(MockSolanaRpc { signature: "sol_sig_mock".into() }),
    );
    let receipt = settler
        .pay_exact(
            &solana_session_key(),
            "recipient_addr",
            Decimal::from(1),
            Caip19Asset::unchecked("solana:mainnet/slip44:501"),
        )
        .await
        .expect("solana pay_exact should succeed");
    assert_eq!(receipt.tx_hash, "sol_sig_mock");
    assert_eq!(receipt.scheme, PaymentScheme::Exact);
    assert_eq!(receipt.chain_id, "solana:mainnet");
}

#[tokio::test]
async fn test_tempo_settler_open_close() {
    // Mock Tempo returns ChannelId on open; assert close returns final receipt.
    let settler = TempoSettler::new("eip155:8453", Box::new(MockTempo::new()));
    let channel_id = settler
        .open_channel(&evm_session_key(), "0xpeer", Decimal::from(100))
        .await
        .expect("tempo open_channel should succeed");
    assert_eq!(channel_id.bytes.len(), 32);

    let receipt =
        settler.close_channel(&channel_id).await.expect("tempo close_channel should succeed");
    assert!(receipt.tx_hash.starts_with("0xclose_"));
    assert_eq!(receipt.amount, Decimal::ZERO); // no streams in this test
    assert_eq!(receipt.chain_id, "eip155:8453");
}

#[tokio::test]
async fn test_payment_scheme_exact() {
    // Assert EvmSettler::supported_schemes() contains both Exact and
    // ExactPlusUserOp.
    let settler = EvmSettler::new(
        "eip155:8453",
        Box::new(MockBundler { tx_hash: "0xabc".into() }),
        Box::new(MockPaymaster { fail: false }),
    );
    let schemes = settler.supported_schemes();
    assert!(schemes.contains(&PaymentScheme::Exact), "EvmSettler should support Exact");
    assert!(
        schemes.contains(&PaymentScheme::ExactPlusUserOp),
        "EvmSettler should support ExactPlusUserOp"
    );
    // SolanaSettler supports only Exact.
    let sol_settler = SolanaSettler::new(
        "solana:mainnet",
        Box::new(MockSolanaRpc { signature: "sol_sig_mock".into() }),
    );
    assert_eq!(sol_settler.supported_schemes(), &[PaymentScheme::Exact]);
    // TempoSettler supports no x402 schemes (MPP-only).
    let tempo_settler = TempoSettler::new("eip155:8453", Box::new(MockTempo::new()));
    assert!(tempo_settler.supported_schemes().is_empty());
}

#[tokio::test]
async fn test_pay_error_variants() {
    // Assert PayError has the required variants by constructing each one and
    // round-tripping it through Display.
    let cases: Vec<PayError> = vec![
        PayError::BundlerError("b".into()),
        PayError::PaymasterError("p".into()),
        PayError::SolanaRpcError("s".into()),
        PayError::TempoError("t".into()),
        PayError::InvalidAmount,
        PayError::InvalidRecipient("r".into()),
        PayError::ChannelNotFound("c".into()),
        PayError::ChannelClosed("c".into()),
        PayError::SigningFailed("k".into()),
    ];
    for err in &cases {
        let _display = err.to_string();
        let _cloned = err.clone();
    }

    // End-to-end: Paymaster failure surfaces as PayError::PaymasterError.
    let settler = EvmSettler::new(
        "eip155:8453",
        Box::new(MockBundler { tx_hash: "0xabc".into() }),
        Box::new(MockPaymaster { fail: true }),
    );
    let err = settler
        .pay_exact(
            &evm_session_key(),
            "0xrecipient",
            Decimal::from(1),
            Caip19Asset::unchecked("eip155:8453/slip44:60"),
        )
        .await
        .expect_err("Paymaster failure should surface");
    assert!(matches!(err, PayError::PaymasterError(_)));
}

// ---------------------------------------------------------------------------
// Additional integration coverage: MPP open → stream → close via PayMpp
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mpp_open_stream_close_round_trip() {
    // Open a Tempo channel, then drive a PayMpp stream handle over it,
    // streaming 3 chunks and closing.
    let tempo = std::sync::Arc::new(MockTempo::new());
    let settler =
        TempoSettler::new("eip155:8453", Box::new(MockTempoShim { inner: tempo.clone() }));
    let channel_id = settler
        .open_channel(&evm_session_key(), "0xpeer", Decimal::from(1000))
        .await
        .expect("open_channel should succeed");

    let pay_mpp = PayMpp::new();
    let handle = pay_mpp
        .open(tempo.as_ref(), channel_id.clone(), evm_session_key(), "0xpeer".to_string())
        .await
        .expect("PayMpp::open should succeed");

    let ack1 = handle.stream_chunk(Decimal::from(10)).await.unwrap();
    assert_eq!(ack1.cumulative, Decimal::from(10));
    let ack2 = handle.stream_chunk(Decimal::from(20)).await.unwrap();
    assert_eq!(ack2.cumulative, Decimal::from(30));
    let ack3 = handle.stream_chunk(Decimal::from(40)).await.unwrap();
    assert_eq!(ack3.cumulative, Decimal::from(70));

    let receipt = handle.close().await.expect("close should succeed");
    assert_eq!(receipt.amount, Decimal::from(70));
    assert!(receipt.tx_hash.starts_with("0xclose_"));
}

/// Shim that lets a `TempoSettler` share its `MockTempo` with the
/// `PayMpp` test path via an `Arc`. The shim just forwards every call.
struct MockTempoShim {
    inner: std::sync::Arc<MockTempo>,
}

#[async_trait]
impl TempoChannelClient for MockTempoShim {
    async fn open(
        &self,
        payer: &SessionKey,
        recipient: &str,
        max_amount: Decimal,
    ) -> Result<ChannelId, PayError> {
        self.inner.open(payer, recipient, max_amount).await
    }
    async fn stream(&self, channel_id: &ChannelId, amount: Decimal) -> Result<Decimal, PayError> {
        self.inner.stream(channel_id, amount).await
    }
    async fn close(&self, channel_id: &ChannelId) -> Result<(String, Decimal), PayError> {
        self.inner.close(channel_id).await
    }
    async fn state(&self, channel_id: &ChannelId) -> Result<oc_pay::ChannelState, PayError> {
        self.inner.state(channel_id).await
    }
}
