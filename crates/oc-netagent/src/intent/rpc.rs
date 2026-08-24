use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::Value;

/// RPC client trait for chain interactions (eth_call, estimateGas, etc.)
pub trait RpcClient: Send + Sync {
    /// Get chain ID.
    fn chain_id(&self) -> &str;

    /// Estimate gas for a transaction (returns gas units).
    fn estimate_gas(
        &self,
        call_data: &CallData,
    ) -> Pin<Box<dyn Future<Output = Result<u64, RpcError>> + Send + '_>>;

    /// Simulate a call without sending (eth_call).
    fn eth_call(
        &self,
        call_data: &CallData,
    ) -> Pin<Box<dyn Future<Output = Result<Value, RpcError>> + Send + '_>>;

    /// Send a raw signed transaction.
    fn send_raw_transaction(
        &self,
        tx_bytes: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<String, RpcError>> + Send + '_>>;

    /// Wait for a transaction receipt.
    fn wait_for_receipt(
        &self,
        tx_hash: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, RpcError>> + Send + '_>>;

    /// Get current gas price (in wei).
    fn gas_price(&self) -> Pin<Box<dyn Future<Output = Result<u64, RpcError>> + Send + '_>>;

    /// Get native token price in USD.
    ///
    /// Implementations without a price feed return an error; the simulation
    /// layer treats that as "price unknown" rather than a fatal failure
    /// (H-05).
    fn native_price_usd(&self) -> Pin<Box<dyn Future<Output = Result<f64, RpcError>> + Send + '_>>;

    /// Get the pending transaction count (nonce) for an address via
    /// `eth_getTransactionCount(address, "pending")` (M-04a).
    ///
    /// Implementations must parse the hex quantity strictly — a malformed
    /// response is an error, never silently zero.
    fn transaction_count(
        &self,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<u64, RpcError>> + Send + '_>>;
}

/// Call data for an EVM transaction.
#[derive(Debug, Clone)]
pub struct CallData {
    pub from: Option<String>,
    pub to: String,
    pub value: Option<String>,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("server error: {0}")]
    Server(String),
    #[error("timeout")]
    Timeout,
    #[error("not found")]
    NotFound,
}

/// Mock RPC client for testing.
///
/// Records `transaction_count` / `send_raw_transaction` call counts so tests
/// can assert on the execute path (M-04). Configuration happens through
/// builder methods before use; the client is immutable while in use.
pub struct MockRpcClient {
    chain_id: String,
    /// Nonce returned by [`RpcClient::transaction_count`].
    nonce: AtomicU64,
    /// When `true`, `native_price_usd` returns an error (H-05 test path).
    native_price_fails: bool,
    transaction_count_calls: AtomicU64,
    send_calls: AtomicU64,
}

impl MockRpcClient {
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
            nonce: AtomicU64::new(0),
            native_price_fails: false,
            transaction_count_calls: AtomicU64::new(0),
            send_calls: AtomicU64::new(0),
        }
    }

    /// Set the nonce returned by `transaction_count`.
    pub fn with_nonce(self, nonce: u64) -> Self {
        self.nonce.store(nonce, Ordering::SeqCst);
        self
    }

    /// Make `native_price_usd` return an error (price feed unavailable).
    pub fn with_failing_native_price(mut self) -> Self {
        self.native_price_fails = true;
        self
    }

    /// Number of `transaction_count` calls recorded so far.
    pub fn transaction_count_calls(&self) -> u64 {
        self.transaction_count_calls.load(Ordering::SeqCst)
    }

    /// Number of `send_raw_transaction` calls recorded so far.
    pub fn send_raw_transaction_calls(&self) -> u64 {
        self.send_calls.load(Ordering::SeqCst)
    }
}

impl RpcClient for MockRpcClient {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    fn estimate_gas(
        &self,
        _call_data: &CallData,
    ) -> Pin<Box<dyn Future<Output = Result<u64, RpcError>> + Send + '_>> {
        Box::pin(async { Ok(21000) })
    }

    fn eth_call(
        &self,
        _call_data: &CallData,
    ) -> Pin<Box<dyn Future<Output = Result<Value, RpcError>> + Send + '_>> {
        Box::pin(async { Ok(Value::Null) })
    }

    fn send_raw_transaction(
        &self,
        _tx_bytes: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<String, RpcError>> + Send + '_>> {
        self.send_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok("0x".to_string() + &"0".repeat(64)) })
    }

    fn wait_for_receipt(
        &self,
        _tx_hash: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, RpcError>> + Send + '_>> {
        Box::pin(async { Ok(serde_json::json!({"status": "0x1", "blockNumber": "0x1"})) })
    }

    fn gas_price(&self) -> Pin<Box<dyn Future<Output = Result<u64, RpcError>> + Send + '_>> {
        Box::pin(async { Ok(1_000_000_000) })
    }

    fn native_price_usd(&self) -> Pin<Box<dyn Future<Output = Result<f64, RpcError>> + Send + '_>> {
        let fails = self.native_price_fails;
        Box::pin(async move {
            if fails {
                Err(RpcError::Parse("no price feed available".to_string()))
            } else {
                Ok(2500.0)
            }
        })
    }

    fn transaction_count(
        &self,
        _address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<u64, RpcError>> + Send + '_>> {
        self.transaction_count_calls.fetch_add(1, Ordering::SeqCst);
        let nonce = self.nonce.load(Ordering::SeqCst);
        Box::pin(async move { Ok(nonce) })
    }
}
