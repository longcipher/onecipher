use std::{future::Future, pin::Pin};

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
    fn native_price_usd(&self) -> Pin<Box<dyn Future<Output = Result<f64, RpcError>> + Send + '_>>;
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
pub struct MockRpcClient {
    chain_id: String,
}

impl MockRpcClient {
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self { chain_id: chain_id.into() }
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
        Box::pin(async { Ok(2500.0) })
    }
}
