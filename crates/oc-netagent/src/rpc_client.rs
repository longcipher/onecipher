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

/// Per-request deadline for a single JSON-RPC call (L-03). A stalled endpoint
/// surfaces as [`RpcError::Timeout`] instead of hanging the caller forever;
/// each receipt poll is bounded by this AND the overall [`RECEIPT_TIMEOUT`]
/// backoff budget.
const RPC_CALL_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// Optional native-token price feed endpoint (see [`Self::with_price_feed`]).
    /// Falls back to the `OC_PRICE_FEED_URL` env var. When neither is set,
    /// [`RpcClient::native_price_usd`] fails closed (explicit error — the
    /// simulation layer degrades USD figures to "unknown" instead of guessing).
    price_feed_url: Option<String>,
}

impl HpxRpcClient {
    /// Construct a new client targeting `rpc_url` for chain `chain_id`.
    ///
    /// `chain_id` follows the CAIP-2 namespace (e.g. `eip155:1`,
    /// `eip155:8453`). `rpc_url` must be an HTTP(S) JSON-RPC endpoint.
    pub fn new(chain_id: impl Into<String>, rpc_url: impl Into<String>) -> Result<Self, RpcError> {
        Ok(Self {
            chain_id: chain_id.into(),
            rpc_url: rpc_url.into(),
            client: hpx::Client::new(),
            price_feed_url: None,
        })
    }

    /// Attach a native-token price feed endpoint.
    ///
    /// The endpoint must return JSON with a numeric `price`, `usd`, or
    /// `result` field (e.g. `{"price": 2500.0}`). Takes precedence over the
    /// `OC_PRICE_FEED_URL` env var. When neither is set, `native_price_usd`
    /// fails closed — callers (notably `simulate_intent`) treat that as
    /// "price unknown", never as zero.
    pub fn with_price_feed(mut self, url: impl Into<String>) -> Self {
        self.price_feed_url = Some(url.into());
        self
    }

    /// Effective price feed URL: explicit value, else `OC_PRICE_FEED_URL` env.
    fn effective_price_feed_url(&self) -> Option<String> {
        self.price_feed_url
            .clone()
            .or_else(|| std::env::var("OC_PRICE_FEED_URL").ok().filter(|v| !v.trim().is_empty()))
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
        let request = async {
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
        };
        // L-03: bound every round trip so a hung endpoint surfaces as a
        // typed timeout instead of blocking the caller indefinitely.
        match tokio::time::timeout(RPC_CALL_TIMEOUT, request).await {
            Ok(result) => result,
            Err(_) => Err(RpcError::Timeout),
        }
    }

    /// `eth_chainId` as a strict `u64` (used by the EIP-1271 / ERC-6492
    /// Sign-In verifier to confirm the endpoint serves the message chain
    /// before any contract call — a wrong-chain endpoint must never see
    /// `isValidSignature`).
    pub async fn eth_chain_id(&self) -> Result<u64, RpcError> {
        let result = self.rpc_call("eth_chainId", json!([])).await?;
        let hex_str = result.as_str().ok_or_else(|| {
            RpcError::Parse(format!("eth_chainId: expected hex string, got {result}"))
        })?;
        parse_hex_u64(hex_str)
    }

    /// Raw `eth_call` returning the decoded response bytes.
    ///
    /// `to` is `None` for deployless create-calls (ERC-6492 simulation);
    /// both `input` and `data` carry the payload for legacy-RPC
    /// compatibility. A malformed `0x` response is a typed parse error,
    /// never silent bytes.
    pub async fn eth_call_bytes(&self, to: Option<&str>, data: &[u8]) -> Result<Vec<u8>, RpcError> {
        let payload = format!("0x{}", hex::encode(data));
        let mut obj = json!({ "input": payload, "data": payload });
        if let Some(to) = to {
            obj["to"] = json!(to);
        }
        let result = self.rpc_call("eth_call", json!([obj, "latest"])).await?;
        let hex_str = result.as_str().ok_or_else(|| {
            RpcError::Parse(format!("eth_call: expected hex data string, got {result}"))
        })?;
        let stripped = hex_str.trim_start_matches("0x");
        if stripped.len() % 2 != 0 || !stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(RpcError::Parse(format!("eth_call: malformed hex data '{hex_str}'")));
        }
        hex::decode(stripped).map_err(|e| RpcError::Parse(format!("eth_call: hex decode: {e}")))
    }

    /// Build the EVM call object from [`CallData`].
    ///
    /// `data` is hex-encoded with a `0x` prefix. A decimal `value` string is
    /// converted to a hex quantity; a malformed decimal is a typed parse
    /// error (M-08) — it is never silently coerced to zero, which would
    /// understate the simulated transfer value.
    fn call_object(call_data: &CallData) -> Result<Value, RpcError> {
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
                // Decimal string → hex quantity (strict; M-08)
                let n: u128 = value.parse().map_err(|e| {
                    RpcError::Parse(format!("invalid decimal value '{value}': {e}"))
                })?;
                json!(format!("0x{n:x}"))
            };
            obj["value"] = hex_value;
        }
        if let Some(data) = &call_data.data {
            obj["data"] = json!(format!("0x{}", hex::encode(data)));
        }
        Ok(obj)
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
            let call_obj = call_obj?;
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
        Box::pin(async move {
            let call_obj = call_obj?;
            self.rpc_call("eth_call", json!([call_obj, "latest"])).await
        })
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
        let feed = self.effective_price_feed_url();
        Box::pin(async move {
            let Some(url) = feed else {
                // Fail-closed: no price feed integrated. The simulation layer
                // (`simulate_intent`) maps this to "price unknown" (USD figures
                // omitted + warning) rather than aborting. Set a feed via
                // `with_price_feed` or the `OC_PRICE_FEED_URL` env var to get
                // real estimates. Never return a guessed constant here — a
                // stale hardcoded price would misstate gas costs.
                return Err(RpcError::Parse(
                    "native_price_usd: no price feed configured (set OC_PRICE_FEED_URL or HpxRpcClient::with_price_feed)".into(),
                ));
            };
            // Minimal price-feed fetch: GET the URL, expect JSON with a numeric
            // `price`, `usd`, or `result` field. Any shape mismatch is a typed
            // parse error (fail-closed), never a silent zero.
            let resp = self
                .client
                .get(&url)
                .send()
                .await
                .map_err(|e| RpcError::Transport(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(RpcError::Transport(format!("price feed HTTP {}", resp.status())));
            }
            let v: Value =
                resp.json().await.map_err(|e| RpcError::Parse(format!("price feed JSON: {e}")))?;
            for key in ["price", "usd", "result"] {
                if let Some(n) = v.get(key).and_then(Value::as_f64) {
                    if n.is_finite() && n >= 0.0 {
                        return Ok(n);
                    }
                }
            }
            Err(RpcError::Parse(format!(
                "price feed response has no numeric price/usd/result: {v}"
            )))
        })
    }

    fn transaction_count(
        &self,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<u64, RpcError>> + Send + '_>> {
        let address = address.to_string();
        Box::pin(async move {
            let result =
                self.rpc_call("eth_getTransactionCount", json!([address, "pending"])).await?;
            let hex_str = result.as_str().ok_or_else(|| {
                RpcError::Parse(format!("transaction_count: expected hex string, got {result}"))
            })?;
            parse_hex_u64(hex_str)
        })
    }
}

/// Parse a hex-encoded quantity (e.g. `"0x5208"` → `21000`).
fn parse_hex_u64(s: &str) -> Result<u64, RpcError> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|e| RpcError::Parse(format!("invalid hex quantity '{s}': {e}")))
}

#[cfg(test)]
#[allow(unsafe_code)]
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
        let obj = HpxRpcClient::call_object(&cd).expect("call object");
        assert_eq!(obj["to"], "0xdef");
        assert_eq!(obj["from"], "0xabc");
        assert_eq!(obj["value"], "0x1");
        assert_eq!(obj["data"], "0xdead");
    }

    #[test]
    fn call_object_omits_optional_fields_when_absent() {
        let cd = CallData { from: None, to: "0xdef".into(), value: None, data: None };
        let obj = HpxRpcClient::call_object(&cd).expect("call object");
        assert_eq!(obj["to"], "0xdef");
        assert!(obj.get("from").is_none());
        assert!(obj.get("value").is_none());
        assert!(obj.get("data").is_none());
    }

    #[test]
    fn call_object_converts_decimal_value_to_hex_quantity() {
        let cd =
            CallData { from: None, to: "0xdef".into(), value: Some("1000000".into()), data: None };
        let obj = HpxRpcClient::call_object(&cd).expect("call object");
        assert_eq!(obj["value"], "0xf4240");
    }

    #[test]
    fn call_object_rejects_malformed_decimal_value() {
        // M-08 regression: a malformed decimal value must be a typed parse
        // error, never a silent zero-value call object.
        let cd = CallData {
            from: None,
            to: "0xdef".into(),
            value: Some("10.5 USDC".into()),
            data: None,
        };
        let err = HpxRpcClient::call_object(&cd).expect_err("must reject malformed decimal");
        assert!(matches!(err, RpcError::Parse(_)), "got: {err}");
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
    async fn native_price_usd_fails_closed_without_feed() {
        // Fail-closed: with no feed configured the error names the fix
        // (OC_PRICE_FEED_URL / with_price_feed) instead of guessing a price.
        let saved = std::env::var("OC_PRICE_FEED_URL").ok();
        unsafe { std::env::remove_var("OC_PRICE_FEED_URL") };
        let c = HpxRpcClient::new("eip155:1", "https://eth.example.com").expect("new");
        let err = c.native_price_usd().await.unwrap_err();
        assert!(format!("{err}").contains("no price feed configured"), "got: {err}");
        if let Some(v) = saved {
            unsafe { std::env::set_var("OC_PRICE_FEED_URL", v) };
        }
    }

    #[test]
    fn with_price_feed_sets_explicit_url() {
        let c = HpxRpcClient::new("eip155:1", "https://eth.example.com")
            .expect("new")
            .with_price_feed("https://price.example.com/eth");
        assert_eq!(c.effective_price_feed_url().as_deref(), Some("https://price.example.com/eth"));
    }
}
