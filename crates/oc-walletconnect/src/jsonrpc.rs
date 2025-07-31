//! JSON-RPC 2.0 codec for WalletConnect v2.
//!
//! Per WC v2 spec, all messages use JSON-RPC 2.0 with non-null `id`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{WcError, WcResult};

/// JSON-RPC 2.0 request object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub params: Value,
    pub id: i64,
}

impl JsonRpcRequest {
    pub fn new(method: impl Into<String>, params: Value, id: i64) -> Self {
        Self { jsonrpc: "2.0".into(), method: method.into(), params, id }
    }
}

/// JSON-RPC 2.0 response object (success or error, never both).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: i64, result: Value) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: Some(result), error: None }
    }

    pub fn error(id: i64, e: JsonRpcError) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: None, error: Some(e) }
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn new(code: JsonRpcErrorCode, message: String) -> Self {
        Self { code: code as i64, message, data: None }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

/// JSON-RPC error codes — WC v2 standard + OneCipher extensions.
///
/// See `docs/design.md` §5.3.4 for full table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum JsonRpcErrorCode {
    UserRejected = 4001,
    Unauthorized = 4100,
    UnsupportedMethod = 4200,
    VaultLocked = 4900,
    PolicyRateLimit = 4031,
    PolicyBudgetExceeded = 4032,
    PolicyWhitelist = 4033,
    PolicyCooldown = 4034,
    PolicyAmountExceeded = 4035,
    PolicyMissing = 4036,
    PolicyExpired = 4037,
    PolicyContractNotWhitelisted = 4038,
    PolicyChainNotWhitelisted = 4039,
    Internal = 5000,
    Signer = 5001,
}

/// Parse a JSON-RPC request from a WC v2 message body (already decrypted).
pub fn parse_request(payload: &[u8]) -> WcResult<JsonRpcRequest> {
    let req: JsonRpcRequest = serde_json::from_slice(payload)?;
    if req.jsonrpc != "2.0" {
        return Err(WcError::InvalidMessage(format!("expected jsonrpc=2.0, got {}", req.jsonrpc)));
    }
    Ok(req)
}

/// Serialize a JSON-RPC response for transmission (will be encrypted by caller).
pub fn serialize_response(resp: &JsonRpcResponse) -> WcResult<Vec<u8>> {
    Ok(serde_json::to_vec(resp)?)
}
