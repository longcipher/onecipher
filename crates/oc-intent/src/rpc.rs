use async_trait::async_trait;
use serde_json::Value;

/// RPC client trait for chain interactions (eth_call, estimateGas, etc.)
#[async_trait]
pub trait RpcClient: Send + Sync {
    /// Get chain ID.
    fn chain_id(&self) -> &str;

    /// Estimate gas for a transaction (returns gas units).
    async fn estimate_gas(&self, call_data: &CallData) -> Result<u64, RpcError>;

    /// Simulate a call without sending (eth_call).
    async fn eth_call(&self, call_data: &CallData) -> Result<Value, RpcError>;

    /// Send a raw signed transaction.
    async fn send_raw_transaction(&self, tx_bytes: &[u8]) -> Result<String, RpcError>;

    /// Wait for a transaction receipt.
    async fn wait_for_receipt(&self, tx_hash: &str) -> Result<Value, RpcError>;

    /// Get current gas price (in wei).
    async fn gas_price(&self) -> Result<u64, RpcError>;

    /// Get native token price in USD.
    async fn native_price_usd(&self) -> Result<f64, RpcError>;
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

#[async_trait]
impl RpcClient for MockRpcClient {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    async fn estimate_gas(&self, _call_data: &CallData) -> Result<u64, RpcError> {
        Ok(21000)
    }

    async fn eth_call(&self, _call_data: &CallData) -> Result<Value, RpcError> {
        Ok(Value::Null)
    }

    async fn send_raw_transaction(&self, _tx_bytes: &[u8]) -> Result<String, RpcError> {
        Ok("0x".to_string() + &"0".repeat(64))
    }

    async fn wait_for_receipt(&self, _tx_hash: &str) -> Result<Value, RpcError> {
        Ok(serde_json::json!({"status": "0x1", "blockNumber": "0x1"}))
    }

    async fn gas_price(&self) -> Result<u64, RpcError> {
        Ok(1_000_000_000) // 1 gwei
    }

    async fn native_price_usd(&self) -> Result<f64, RpcError> {
        Ok(2500.0) // mock ETH price
    }
}
