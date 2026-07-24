//! Integration tests for `oc-pay` settlers with mock Bundler / Paymaster /
//! Solana RPC / Tempo clients.
//!
//! These mirror the contract surface required by the T18 spec — they exercise
//! the `PaymentSettler` trait end-to-end with mockable trait-object clients
//! and assert the receipts / errors match the spec.

use std::{collections::HashMap, future::Future, pin::Pin, sync::Mutex};

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

impl BundlerClient for MockBundler {
    fn submit_user_op(
        &self,
        _user_op: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<String, PayError>> + Send + '_>> {
        Box::pin(async { Ok(self.tx_hash.clone()) })
    }
}

struct MockPaymaster {
    fail: bool,
}

impl PaymasterClient for MockPaymaster {
    fn sponsor<'a>(
        &'a self,
        _user_op: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PayError>> + Send + 'a>> {
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                return Err(PayError::PaymasterError("sponsor refused".into()));
            }
            _user_op.extend_from_slice(&[0u8; 52]);
            Ok(())
        })
    }
}

struct MockSolanaRpc {
    signature: String,
}

impl SolanaRpcClient for MockSolanaRpc {
    fn send_transaction(
        &self,
        _tx: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<String, PayError>> + Send + '_>> {
        Box::pin(async { Ok(self.signature.clone()) })
    }

    fn get_account(
        &self,
        _address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, PayError>> + Send + '_>> {
        Box::pin(async { Ok(Some(vec![0x01])) })
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
        self.states.lock().expect("states poisoned").insert(id.clone(), oc_pay::ChannelState::Open);
        self.streamed.lock().expect("streamed poisoned").insert(id.clone(), Decimal::ZERO);
        Box::pin(async move { Ok(id) })
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
    ) -> Pin<Box<dyn Future<Output = Result<(String, Decimal), PayError>> + Send + '_>> {
        let mut states = self.states.lock().expect("states poisoned");
        let state = states
            .get(channel_id)
            .copied()
            .ok_or_else(|| PayError::ChannelNotFound(channel_id.hex.clone()));
        let hex = channel_id.hex.clone();
        match state {
            Ok(oc_pay::ChannelState::Closed) => {
                return Box::pin(async move { Err(PayError::ChannelClosed(hex)) });
            }
            Err(e) => return Box::pin(async { Err(e) }),
            _ => {}
        }
        states.insert(channel_id.clone(), oc_pay::ChannelState::Closed);
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
    ) -> Pin<Box<dyn Future<Output = Result<oc_pay::ChannelState, PayError>> + Send + '_>> {
        let states = self.states.lock().expect("states poisoned");
        let result = states
            .get(channel_id)
            .copied()
            .ok_or_else(|| PayError::ChannelNotFound(channel_id.hex.clone()));
        Box::pin(async move { result })
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
    let settler = TempoSettler::new("eip155:8453", Box::new(MockTempo::new()));
    let channel_id = settler
        .open_channel(&evm_session_key(), "0xpeer", Decimal::from(100))
        .await
        .expect("tempo open_channel should succeed");
    assert_eq!(channel_id.bytes.len(), 32);

    let receipt =
        settler.close_channel(&channel_id).await.expect("tempo close_channel should succeed");
    assert!(receipt.tx_hash.starts_with("0xclose_"));
    assert_eq!(receipt.amount, Decimal::ZERO);
    assert_eq!(receipt.chain_id, "eip155:8453");
}

#[tokio::test]
async fn test_payment_scheme_exact() {
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
    let sol_settler = SolanaSettler::new(
        "solana:mainnet",
        Box::new(MockSolanaRpc { signature: "sol_sig_mock".into() }),
    );
    assert_eq!(sol_settler.supported_schemes(), &[PaymentScheme::Exact]);
    let tempo_settler = TempoSettler::new("eip155:8453", Box::new(MockTempo::new()));
    assert!(tempo_settler.supported_schemes().is_empty());
}

#[tokio::test]
async fn test_pay_error_variants() {
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

impl TempoChannelClient for MockTempoShim {
    fn open(
        &self,
        payer: &SessionKey,
        recipient: &str,
        max_amount: Decimal,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelId, PayError>> + Send + '_>> {
        self.inner.open(payer, recipient, max_amount)
    }
    fn stream(
        &self,
        channel_id: &ChannelId,
        amount: Decimal,
    ) -> Pin<Box<dyn Future<Output = Result<Decimal, PayError>> + Send + '_>> {
        self.inner.stream(channel_id, amount)
    }
    fn close(
        &self,
        channel_id: &ChannelId,
    ) -> Pin<Box<dyn Future<Output = Result<(String, Decimal), PayError>> + Send + '_>> {
        self.inner.close(channel_id)
    }
    fn state(
        &self,
        channel_id: &ChannelId,
    ) -> Pin<Box<dyn Future<Output = Result<oc_pay::ChannelState, PayError>> + Send + '_>> {
        self.inner.state(channel_id)
    }
}
