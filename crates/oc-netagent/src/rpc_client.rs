//! Real EVM JSON-RPC client backed by `hpx`, implementing [`crate::intent::RpcClient`].
//!
//! Used by the `intent` CLI subcommands when `--rpc-url` is provided. When
//! `--rpc-url` is absent, the CLI falls back to [`crate::intent::MockRpcClient`].
//!
//! The client is chain-agnostic in the sense that it only speaks EVM JSON-RPC
//! (eth_call, eth_estimateGas, eth_sendRawTransaction, …). Solana / Bitcoin
//! support will be added in a later stage once the `RpcClient` trait grows
//! chain-specific methods.

use std::{future::Future, pin::Pin, time::Duration};

use backon::{ExponentialBuilder, Retryable};
use serde_json::{Value, json};
use tracing::debug;

use crate::intent::rpc::{CallData, RpcClient, RpcError};

/// Overall budget for [`RpcClient::wait_for_receipt`] before returning
/// [`RpcError::Timeout`].
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// EVM JSON-RPC client backed by `hpx`.
///
/// Stateless aside from the reused [`hpx::Client`] connection pool. All trait
/// methods take `&self`, so a single instance can be shared across tasks via
/// `&HpxRpcClient`.
///
/// Does not implement `Debug` because [`hpx::Client`] does not.
pub struct HpxRpcClient {
    chain_id: String,
    rpc_url: String,
    client: hpx::Client,
}

impl HpxRpcClient {
    /// Construct a new client targeting `rpc_url` for chain `chain_id`.
    ///
    /// `chain_id` follows the CAIP-2 namespace (e.g. `eip155:1`,
    /// `eip155:8453`). `rpc_url` must be an HTTP(S) JSON-RPC endpoint.
    pub fn new(chain_id: impl Into<String>, rpc_url: impl Into<String>) -> Result<Self, RpcError> {
        Ok(Self { chain_id: chain_id.into(), rpc_url: rpc_url.into(), client: hpx::Client::new() })
    }

    /// Send a JSON-RPC 2.0 POST and return the `result` field.
    ///
    /// Surfaces transport failures as [`RpcError::Transport`], JSON-RPC server
    /// errors as [`RpcError::Server`], and response body parse failures as
    /// [`RpcError::Parse`].
    async fn rpc_call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp = self
            .client
            .post(&self.rpc_url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(RpcError::Transport(format!("HTTP {status}: {text}")));
        }

        let v: Value = resp.json().await.map_err(|e| RpcError::Parse(e.to_string()))?;

        if let Some(err) = v.get("error") {
            return Err(RpcError::Server(err.to_string()));
        }

        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Build the EVM call object from [`CallData`].
    ///
    /// `data` is hex-encoded with a `0x` prefix. `value` is passed through
    /// as-is (callers are expected to provide a hex-encoded wei amount).
    fn call_object(call_data: &CallData) -> Value {
        let mut obj = json!({
            "to": call_data.to,
        });
        if let Some(from) = &call_data.from {
            obj["from"] = json!(from);
        }
        if let Some(value) = &call_data.value {
            // Normalize to hex quantity format for EVM JSON-RPC consistency
            let hex_value = if value.starts_with("0x") {
                json!(value)
            } else {
                // Decimal string → hex quantity
                let n: u128 = value.parse().unwrap_or(0);
                json!(format!("0x{:x}", n))
            };
            obj["value"] = hex_value;
        }
        if let Some(data) = &call_data.data {
            obj["data"] = json!(format!("0x{}", hex::encode(data)));
        }
        obj
    }
}

impl RpcClient for HpxRpcClient {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    fn estimate_gas(
        &self,
        call_data: &CallData,
    ) -> Pin<Box<dyn Future<Output = Result<u64, RpcError>> + Send + '_>> {
        let call_obj = Self::call_object(call_data);
        Box::pin(async move {
            let result = self.rpc_call("eth_estimateGas", json!([call_obj])).await?;
            let hex_str = result.as_str().ok_or_else(|| {
                RpcError::Parse(format!("estimate_gas: expected hex string, got {result}"))
            })?;
            parse_hex_u64(hex_str)
        })
    }

    fn eth_call(
        &self,
        call_data: &CallData,
    ) -> Pin<Box<dyn Future<Output = Result<Value, RpcError>> + Send + '_>> {
        let call_obj = Self::call_object(call_data);
        Box::pin(async move { self.rpc_call("eth_call", json!([call_obj, "latest"])).await })
    }

    fn send_raw_transaction(
        &self,
        tx_bytes: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<String, RpcError>> + Send + '_>> {
        let hex_tx = format!("0x{}", hex::encode(tx_bytes));
        Box::pin(async move {
            let result = self.rpc_call("eth_sendRawTransaction", json!([hex_tx])).await?;
            result.as_str().map(String::from).ok_or_else(|| {
                RpcError::Parse(format!(
                    "send_raw_transaction: expected tx hash string, got {result}"
                ))
            })
        })
    }

    fn wait_for_receipt(
        &self,
        tx_hash: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, RpcError>> + Send + '_>> {
        let tx_hash = tx_hash.to_string();
        Box::pin(async move {
            // Backoff policy (replaces the previous hand-rolled fixed 2 s loop):
            //
            // - Exponential 500 ms → 4 s cap, jittered. The old fixed interval made every
            //   concurrent `wait_for_receipt` hit the RPC endpoint in lockstep; jitter breaks that
            //   thundering herd.
            // - `with_total_delay` enforces the same overall 60 s budget the manual `Instant`
            //   deadline provided.
            let backoff = ExponentialBuilder::default()
                .with_min_delay(Duration::from_millis(500))
                .with_max_delay(Duration::from_secs(4))
                .with_total_delay(Some(RECEIPT_TIMEOUT))
                .with_jitter()
                .without_max_times();

            let poll = || async {
                let result = self.rpc_call("eth_getTransactionReceipt", json!([tx_hash])).await?;
                if result.is_null() {
                    return Err(RpcError::NotFound);
                }
                Ok(result)
            };

            poll.retry(backoff)
                // A pending receipt is `NotFound`; transient transport/server
                // blips are also retried rather than aborting the whole wait,
                // which the previous `?` propagation did.
                .when(|e| {
                    matches!(e, RpcError::NotFound | RpcError::Transport(_) | RpcError::Server(_))
                })
                .notify(|e, delay| {
                    debug!(tx_hash, error = %e, ?delay, "receipt not yet available; polling");
                })
                .await
                .map_err(|e| match e {
                    // Exhausting the delay budget is a timeout, not "no such tx".
                    RpcError::NotFound => RpcError::Timeout,
                    other => other,
                })
        })
    }

    fn gas_price(&self) -> Pin<Box<dyn Future<Output = Result<u64, RpcError>> + Send + '_>> {
        Box::pin(async move {
            let result = self.rpc_call("eth_gasPrice", json!([])).await?;
            let hex_str = result.as_str().ok_or_else(|| {
                RpcError::Parse(format!("gas_price: expected hex string, got {result}"))
            })?;
            parse_hex_u64(hex_str)
        })
    }

    fn native_price_usd(&self) -> Pin<Box<dyn Future<Output = Result<f64, RpcError>> + Send + '_>> {
        Box::pin(async {
            Err(RpcError::Parse(
                "native_price_usd not yet implemented; no price feed integrated".into(),
            ))
        })
    }
}

/// Parse a hex-encoded quantity (e.g. `"0x5208"` → `21000`).
fn parse_hex_u64(s: &str) -> Result<u64, RpcError> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|e| RpcError::Parse(format!("invalid hex quantity '{s}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_u64_handles_0x_prefix() {
        assert_eq!(parse_hex_u64("0x5208").unwrap(), 21_000);
        assert_eq!(parse_hex_u64("0x3b9aca00").unwrap(), 1_000_000_000);
    }

    #[test]
    fn parse_hex_u64_handles_no_prefix() {
        assert_eq!(parse_hex_u64("5208").unwrap(), 21_000);
    }

    #[test]
    fn parse_hex_u64_rejects_invalid() {
        assert!(parse_hex_u64("0xnope").is_err());
    }

    #[test]
    fn call_object_includes_all_fields_when_present() {
        let cd = CallData {
            from: Some("0xabc".into()),
            to: "0xdef".into(),
            value: Some("0x1".into()),
            data: Some(vec![0xde, 0xad]),
        };
        let obj = HpxRpcClient::call_object(&cd);
        assert_eq!(obj["to"], "0xdef");
        assert_eq!(obj["from"], "0xabc");
        assert_eq!(obj["value"], "0x1");
        assert_eq!(obj["data"], "0xdead");
    }

    #[test]
    fn call_object_omits_optional_fields_when_absent() {
        let cd = CallData { from: None, to: "0xdef".into(), value: None, data: None };
        let obj = HpxRpcClient::call_object(&cd);
        assert_eq!(obj["to"], "0xdef");
        assert!(obj.get("from").is_none());
        assert!(obj.get("value").is_none());
        assert!(obj.get("data").is_none());
    }

    #[test]
    fn new_constructs_client_with_chain_id_and_url() {
        let c = HpxRpcClient::new("eip155:1", "https://eth.example.com").expect("new");
        assert_eq!(c.chain_id, "eip155:1");
        assert_eq!(c.rpc_url, "https://eth.example.com");
    }

    #[tokio::test]
    async fn chain_id_returns_configured_value() {
        let c = HpxRpcClient::new("eip155:8453", "https://base.example.com").expect("new");
        assert_eq!(c.chain_id(), "eip155:8453");
    }

    #[tokio::test]
    async fn native_price_usd_returns_not_implemented() {
        let c = HpxRpcClient::new("eip155:1", "https://eth.example.com").expect("new");
        let err = c.native_price_usd().await.unwrap_err();
        assert!(format!("{err}").contains("not yet implemented"));
    }
}
