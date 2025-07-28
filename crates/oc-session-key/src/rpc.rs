//! On-chain RPC abstraction.
//!
//! Per the design (T9 step 4): real on-chain RPC calls happen in `oc-netagent`
//! (Phase D). Phase 1 ships only [`MockRpcClient`] for tests. The trait is
//! `#[async_trait]` but the crate does NOT depend on tokio (R56) — futures are
//! runtime-agnostic; the Net-Agent supplies the runtime.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;

use crate::{error::SessionKeyError, types::SolanaInstruction};

/// Trait abstracting on-chain RPC calls. Real implementations (ethers-rs /
/// alloy / solana-client) live in `oc-netagent`. Phase 1 ships only
/// [`MockRpcClient`] for tests.
#[async_trait]
pub trait RpcClient: Send + Sync {
    /// Send an EVM transaction (`to` + calldata) and return the tx hash.
    async fn send_evm_tx(&self, to: &str, calldata: &[u8]) -> Result<String, SessionKeyError>;
    /// Call an EVM view function (eth_call) and return the raw return bytes.
    async fn call_evm_view(&self, to: &str, calldata: &[u8]) -> Result<Vec<u8>, SessionKeyError>;
    /// Send a Solana transaction (one or more instructions) and return the signature.
    async fn send_solana_tx(
        &self,
        instructions: Vec<SolanaInstruction>,
    ) -> Result<String, SessionKeyError>;
    /// Fetch a Solana account's data (returns `None` if the account does not exist).
    async fn get_solana_account(&self, address: &str) -> Result<Option<Vec<u8>>, SessionKeyError>;
}

/// Shared call counters for [`MockRpcClient`].
///
/// Held behind an `Arc` so tests can inspect call counts after the
/// `MockRpcClient` has been moved into a `Box<dyn RpcClient>`.
#[derive(Default)]
pub struct MockRpcCounters {
    /// Number of times `send_evm_tx` was called.
    pub evm_tx_calls: AtomicUsize,
    /// Number of times `call_evm_view` was called.
    pub evm_view_calls: AtomicUsize,
    /// Number of times `send_solana_tx` was called.
    pub solana_tx_calls: AtomicUsize,
    /// Number of times `get_solana_account` was called.
    pub solana_account_calls: AtomicUsize,
}

impl MockRpcCounters {
    /// Number of times `send_evm_tx` was called.
    pub fn evm_tx(&self) -> usize {
        self.evm_tx_calls.load(Ordering::Relaxed)
    }

    /// Number of times `send_solana_tx` was called.
    pub fn solana_tx(&self) -> usize {
        self.solana_tx_calls.load(Ordering::Relaxed)
    }
}

/// Mock RPC client for tests. Returns configurable responses and counts calls
/// for assertions.
///
/// Phase 1 only — real RPC implementations live in `oc-netagent` (Phase D).
pub struct MockRpcClient {
    /// Response returned by `send_evm_tx`.
    pub evm_tx_response: Result<String, SessionKeyError>,
    /// Response returned by `call_evm_view`.
    pub evm_view_response: Result<Vec<u8>, SessionKeyError>,
    /// Response returned by `send_solana_tx`.
    pub solana_tx_response: Result<String, SessionKeyError>,
    /// Response returned by `get_solana_account`.
    pub solana_account_response: Result<Option<Vec<u8>>, SessionKeyError>,
    /// Shared call counters (cloneable handle — see [`MockRpcCounters`]).
    pub counters: Arc<MockRpcCounters>,
}

impl MockRpcClient {
    /// Build a mock client that returns successful responses for every call.
    pub fn ok() -> Self {
        Self {
            evm_tx_response: Ok("0xdeadbeef".to_string()),
            evm_view_response: Ok(vec![0x01]),
            solana_tx_response: Ok("sol_sig_mock".to_string()),
            solana_account_response: Ok(Some(vec![0x01])),
            counters: Arc::new(MockRpcCounters::default()),
        }
    }

    /// Returns a cloneable handle to the call counters, so tests can inspect
    /// call counts after this client has been moved into a `Box<dyn RpcClient>`.
    pub fn counters(&self) -> Arc<MockRpcCounters> {
        Arc::clone(&self.counters)
    }
}

#[async_trait]
impl RpcClient for MockRpcClient {
    async fn send_evm_tx(&self, _to: &str, _calldata: &[u8]) -> Result<String, SessionKeyError> {
        self.counters.evm_tx_calls.fetch_add(1, Ordering::Relaxed);
        self.evm_tx_response.clone()
    }

    async fn call_evm_view(&self, _to: &str, _calldata: &[u8]) -> Result<Vec<u8>, SessionKeyError> {
        self.counters.evm_view_calls.fetch_add(1, Ordering::Relaxed);
        self.evm_view_response.clone()
    }

    async fn send_solana_tx(
        &self,
        _instructions: Vec<SolanaInstruction>,
    ) -> Result<String, SessionKeyError> {
        self.counters.solana_tx_calls.fetch_add(1, Ordering::Relaxed);
        self.solana_tx_response.clone()
    }

    async fn get_solana_account(&self, _address: &str) -> Result<Option<Vec<u8>>, SessionKeyError> {
        self.counters.solana_account_calls.fetch_add(1, Ordering::Relaxed);
        self.solana_account_response.clone()
    }
}
