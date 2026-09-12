//! Real session-key RPC bridge (`real-rpc` feature).
//!
//! Implements the `oc-session-key` RPC traits (`EvmRpcClient`,
//! `EvmBundlerClient`, `SolanaRpcClient`) on top of raw JSON-RPC over `hpx`.
//! This is the ONLY place where session-key provider logic touches the
//! network: `oc-session-key` itself stays pure (R56 — no tokio/reqwest/hyper),
//! and `alloy` / `solana-client` typed SDKs (when adopted) will live HERE in
//! `oc-netagent` (or in `oc-wallet` behind its `rpc` feature), never in the
//! leaf. The current bridge speaks plain JSON-RPC (`eth_call`,
//! `eth_sendRawTransaction`, `eth_estimateGas`, bundler
//! `eth_sendUserOperation`, Solana `sendTransaction`/`getAccountInfo`/`getSlot`)
//! so it adds zero new dependencies.
//!
//! Mock clients remain in `oc-session-key` for unit tests; production wires
//! these bridges with the `SessionKeyProvider` impls in
//! `oc-session-key::mock_v1` (which are logic-only and runtime-agnostic).

use std::{future::Future, pin::Pin, time::Duration};

use oc_session_key::{SessionKeyError, SolanaInstruction};
use serde_json::{Value, json};

type FutureResult<'a, T> = Pin<Box<dyn Future<Output = Result<T, SessionKeyError>> + Send + 'a>>;

/// Per-request deadline for a single JSON-RPC round trip.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared JSON-RPC POST helper (EVM + Solana + bundler share the shape).
async fn rpc_post(
    client: &hpx::Client,
    endpoint: &str,
    method: &str,
    params: Value,
) -> Result<Value, SessionKeyError> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let fut = async {
        let resp = client
            .post(endpoint)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| SessionKeyError::RpcFailed(format!("transport: {e}")))?;
        if !resp.status().is_success() {
            return Err(SessionKeyError::RpcFailed(format!("HTTP {}", resp.status())));
        }
        let v: Value =
            resp.json().await.map_err(|e| SessionKeyError::RpcFailed(format!("parse: {e}")))?;
        if let Some(err) = v.get("error") {
            return Err(SessionKeyError::RpcFailed(format!("server: {err}")));
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    };
    match tokio::time::timeout(RPC_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(SessionKeyError::RpcFailed("timeout".to_string())),
    }
}

/// Parse a hex quantity (`"0x5208"` → `21000`).
fn parse_hex_u64(s: &str) -> Result<u64, SessionKeyError> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|e| SessionKeyError::InvalidPayload(format!("invalid hex quantity '{s}': {e}")))
}

/// Real EVM RPC bridge (eth_call / sendRawTransaction / estimateGas).
pub struct NetAgentEvmRpcClient {
    endpoint: String,
    client: hpx::Client,
}

impl NetAgentEvmRpcClient {
    /// Target an EVM JSON-RPC endpoint (e.g. Base, Ethereum).
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self { endpoint: endpoint.into(), client: hpx::Client::new() }
    }
}

impl oc_session_key::mock_v1::EvmRpcClient for NetAgentEvmRpcClient {
    fn eth_call(&self, to: &str, data: &[u8]) -> FutureResult<'_, Vec<u8>> {
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();
        let call = json!([{ "to": to, "data": format!("0x{}", hex::encode(data)) }]);
        Box::pin(async move {
            let v = rpc_post(&client, &endpoint, "eth_call", json!([call, "latest"])).await?;
            let s = v.as_str().ok_or_else(|| {
                SessionKeyError::InvalidPayload(format!("eth_call: expected hex, got {v}"))
            })?;
            hex::decode(s.trim_start_matches("0x")).map_err(|e| {
                SessionKeyError::InvalidPayload(format!("eth_call returndata hex: {e}"))
            })
        })
    }

    fn send_transaction(&self, tx: &[u8]) -> FutureResult<'_, String> {
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();
        let hex_tx = format!("0x{}", hex::encode(tx));
        Box::pin(async move {
            let v = rpc_post(&client, &endpoint, "eth_sendRawTransaction", json!([hex_tx])).await?;
            v.as_str().map(String::from).ok_or_else(|| {
                SessionKeyError::InvalidPayload(format!("sendRawTransaction: got {v}"))
            })
        })
    }

    fn estimate_gas(&self, to: &str, data: &[u8]) -> FutureResult<'_, u64> {
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();
        let call = json!([{ "to": to, "data": format!("0x{}", hex::encode(data)) }]);
        Box::pin(async move {
            let v = rpc_post(&client, &endpoint, "eth_estimateGas", json!([call])).await?;
            let s = v.as_str().ok_or_else(|| {
                SessionKeyError::InvalidPayload(format!("estimateGas: expected hex, got {v}"))
            })?;
            parse_hex_u64(s)
        })
    }
}

/// Real ERC-4337 bundler bridge (`eth_sendUserOperation` /
/// `eth_getUserOperationReceipt`).
pub struct NetAgentBundlerClient {
    endpoint: String,
    client: hpx::Client,
}

impl NetAgentBundlerClient {
    /// Target a bundler endpoint (e.g. Pimlico, Stackup).
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self { endpoint: endpoint.into(), client: hpx::Client::new() }
    }
}

impl oc_session_key::mock_v1::EvmBundlerClient for NetAgentBundlerClient {
    fn send_user_operation(&self, user_op: &[u8]) -> FutureResult<'_, String> {
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();
        let hex_op = format!("0x{}", hex::encode(user_op));
        Box::pin(async move {
            let v = rpc_post(&client, &endpoint, "eth_sendUserOperation", json!([hex_op])).await?;
            v.as_str().map(String::from).ok_or_else(|| {
                SessionKeyError::InvalidPayload(format!("sendUserOperation: got {v}"))
            })
        })
    }

    fn get_user_operation_receipt(&self, hash: &str) -> FutureResult<'_, Value> {
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();
        let hash = hash.to_string();
        Box::pin(async move {
            rpc_post(&client, &endpoint, "eth_getUserOperationReceipt", json!([hash])).await
        })
    }
}

/// Real Solana RPC bridge (`sendTransaction` / `getAccountInfo` / `getSlot`).
pub struct NetAgentSolanaRpcClient {
    endpoint: String,
    client: hpx::Client,
}

impl NetAgentSolanaRpcClient {
    /// Target a Solana JSON-RPC endpoint.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self { endpoint: endpoint.into(), client: hpx::Client::new() }
    }
}

impl oc_session_key::mock_v1::SolanaRpcClient for NetAgentSolanaRpcClient {
    fn send_transaction(&self, instructions: Vec<SolanaInstruction>) -> FutureResult<'_, String> {
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();
        Box::pin(async move {
            // Simplified envelope: base64 of the JSON-encoded instruction set.
            // A future `solana-client` upgrade will build a real versioned
            // transaction here; the provider logic is unchanged.
            let payload = serde_json::to_string(&json!(
                instructions
                    .iter()
                    .map(|ix| json!({
                        "program_id": ix.program_id,
                        "accounts": ix.accounts,
                        "data": hex::encode(&ix.data),
                    }))
                    .collect::<Vec<_>>()
            ))
            .map_err(|e| SessionKeyError::InvalidPayload(e.to_string()))?;
            let v = rpc_post(&client, &endpoint, "sendTransaction", json!([payload])).await?;
            v.as_str()
                .map(String::from)
                .ok_or_else(|| SessionKeyError::InvalidPayload(format!("sendTransaction: got {v}")))
        })
    }

    fn get_account(&self, address: &str) -> FutureResult<'_, Option<Vec<u8>>> {
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();
        let address = address.to_string();
        Box::pin(async move {
            let v = rpc_post(
                &client,
                &endpoint,
                "getAccountInfo",
                json!([address, { "encoding": "base64" }]),
            )
            .await?;
            if v.is_null() {
                return Ok(None);
            }
            let data_b64 = v
                .get("value")
                .and_then(|val| val.get("data"))
                .and_then(|d| d.get(0))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SessionKeyError::InvalidPayload(format!("getAccountInfo shape: {v}"))
                })?;
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data_b64)
                .map_err(|e| SessionKeyError::InvalidPayload(format!("account base64: {e}")))?;
            Ok(Some(bytes))
        })
    }

    fn get_slot(&self) -> FutureResult<'_, u64> {
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();
        Box::pin(async move {
            let v = rpc_post(&client, &endpoint, "getSlot", json!([])).await?;
            v.as_u64().ok_or_else(|| SessionKeyError::InvalidPayload(format!("getSlot: got {v}")))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridges_construct_without_network() {
        let evm = NetAgentEvmRpcClient::new("https://eth.example.com");
        assert_eq!(evm.endpoint, "https://eth.example.com");
        let bundler = NetAgentBundlerClient::new("https://bundler.example.com");
        assert_eq!(bundler.endpoint, "https://bundler.example.com");
        let sol = NetAgentSolanaRpcClient::new("https://sol.example.com");
        assert_eq!(sol.endpoint, "https://sol.example.com");
    }

    #[test]
    fn parse_hex_u64_bridge_handles_quantities() {
        assert_eq!(parse_hex_u64("0x5208").unwrap(), 21_000);
        assert!(parse_hex_u64("0xnope").is_err());
    }
}
