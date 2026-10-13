//! Read-only JSON-RPC proxy for the OCWP `oc_rpc` method (design §5.2).
//!
//! dApp read calls (`eth_call`, `eth_estimateGas`, balances, ...) are proxied
//! through the daemon so the extension needs no broad `host_permissions`, RPC
//! endpoints stay centrally managed, and every call is rate-limited and
//! bounded. Broadcasting (`eth_sendRawTransaction`) is deliberately NOT in the
//! allowlist — only `oc_send_transaction` broadcasts, behind consent + policy.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use super::{errors::OcwpError, registries::ChainRegistry};

/// OCWP protocol version implemented by this daemon.
pub(super) const PROTOCOL_VERSION: u32 = 1;

/// Read-only methods a dApp may proxy through the daemon.
pub(super) const RPC_ALLOWLIST: &[&str] = &[
    "eth_chainId",
    "eth_blockNumber",
    "eth_getBalance",
    "eth_call",
    "eth_estimateGas",
    "eth_getTransactionCount",
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_getTransactionReceipt",
    "eth_getCode",
];

/// Per-origin token-bucket rate limiter (30 rps sustained, burst 60).
pub(crate) struct RpcRateLimiter {
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
    rate_per_sec: f64,
    burst: f64,
}

impl RpcRateLimiter {
    pub(crate) fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self { buckets: Mutex::new(HashMap::new()), rate_per_sec, burst }
    }

    /// Consume one token for `key`. Returns `false` when the bucket is empty.
    pub(crate) fn check(&self, key: &str) -> bool {
        // The bucket key must not be forgeable by the client: `origin` and
        // `session_id` are both client-supplied, so a single concatenated key
        // would let a caller hop buckets by varying which one it varies. Use
        // a length-prefixed key so ("ab","c") and ("a","bc") can never
        // collide into one bucket.
        let mut keyed = String::with_capacity(key.len() + 16);
        keyed.push_str(&key.len().to_string());
        keyed.push('|');
        keyed.push_str(key);
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let entry = buckets.entry(keyed).or_insert((self.burst, now));
        let elapsed = now.duration_since(entry.1).as_secs_f64();
        entry.1 = now;
        entry.0 = elapsed.mul_add(self.rate_per_sec, entry.0).min(self.burst);
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The two buckets an `oc_rpc` call is charged to (design §3.4).
///
/// Both are daemon-vouchable: the extension origin comes from the connection
/// header, the session id from the store. A dApp origin is deliberately not
/// here — it is client-supplied, so keying a budget on it would let a caller
/// mint itself fresh quota by varying the string.
pub(super) struct RateBuckets<'a> {
    /// The validated `chrome-extension://<id>`.
    pub extension: &'a str,
    /// `"<extension origin>|<session id>"` — one budget per session.
    pub session: String,
    limiter: &'a RpcRateLimiter,
}

impl<'a> RateBuckets<'a> {
    pub(super) fn new(extension: &'a str, session_id: &str, limiter: &'a RpcRateLimiter) -> Self {
        Self { extension, session: format!("{extension}|{session_id}"), limiter }
    }

    /// Charge both buckets. Both must have budget: a dApp cannot spend the
    /// whole session's quota, and one session cannot spend the extension's.
    fn charge(&self) -> bool {
        self.limiter.check(self.extension) && self.limiter.check(&self.session)
    }
}

/// Proxy one read-only JSON-RPC call to the chain's endpoint.
pub(super) fn proxy(
    chain_registry: &ChainRegistry,
    config: &oc_core::Config,
    buckets: &RateBuckets<'_>,
    chain_id: &str,
    method: &str,
    params: &Value,
) -> Result<Value, OcwpError> {
    if !RPC_ALLOWLIST.contains(&method) {
        return Err(OcwpError::unsupported(format!(
            "method '{method}' is not proxied; use oc_send_transaction for broadcasts"
        )));
    }
    if !buckets.charge() {
        return Err(OcwpError::new(
            super::errors::CODE_RATE_LIMITED,
            "RPC proxy rate limit exceeded",
        ));
    }
    let rpc_url = chain_registry.rpc_url(chain_id, config).ok_or_else(|| {
        OcwpError::invalid_params(format!("no RPC endpoint for chain '{chain_id}'"))
    })?;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    let response_text = crate::shared_runtime()
        .block_on(async {
            let client = hpx::Client::new();
            let resp = client
                .post(&rpc_url)
                .header("Content-Type", "application/json")
                .body(body)
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .map_err(|e| format!("rpc request failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("rpc endpoint returned {}", resp.status()));
            }
            resp.text().await.map_err(|e| format!("rpc read failed: {e}"))
        })
        .map_err(|e| {
            tracing::warn!(error = %e, "ocwp: proxied rpc call failed");
            OcwpError::internal("rpc endpoint unreachable")
        })?;
    // 1 MiB response cap (design §5.2).
    if response_text.len() > 1024 * 1024 {
        return Err(OcwpError::internal("rpc response too large"));
    }
    let parsed: Value = serde_json::from_str(&response_text)
        .map_err(|_| OcwpError::internal("rpc endpoint returned malformed JSON"))?;
    if let Some(error) = parsed.get("error") {
        // Surface upstream JSON-RPC errors verbatim (code + message).
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(-32000);
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("upstream rpc error")
            .to_string();
        return Err(OcwpError::new(code as i32, message));
    }
    parsed.get("result").cloned().ok_or_else(|| OcwpError::internal("rpc response missing result"))
}

/// Internal JSON-RPC call used by the daemon itself (nonce/fee estimation,
/// simulation). Not allowlist-gated and not rate-limited — callers invoke it a
/// bounded number of times per signing request.
pub(super) fn internal_call(
    chain_registry: &ChainRegistry,
    config: &oc_core::Config,
    chain_id: &str,
    method: &str,
    params: Value,
) -> Result<Value, OcwpError> {
    let rpc_url = chain_registry.rpc_url(chain_id, config).ok_or_else(|| {
        OcwpError::invalid_params(format!("no RPC endpoint for chain '{chain_id}'"))
    })?;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    let response_text = crate::shared_runtime()
        .block_on(async {
            let client = hpx::Client::new();
            let resp = client
                .post(&rpc_url)
                .header("Content-Type", "application/json")
                .body(body)
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .map_err(|e| format!("rpc request failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("rpc endpoint returned {}", resp.status()));
            }
            resp.text().await.map_err(|e| format!("rpc read failed: {e}"))
        })
        .map_err(|e| {
            tracing::warn!(error = %e, "ocwp: internal rpc call failed");
            OcwpError::internal("rpc endpoint unreachable")
        })?;
    let parsed: Value = serde_json::from_str(&response_text)
        .map_err(|_| OcwpError::internal("rpc endpoint returned malformed JSON"))?;
    if let Some(error) = parsed.get("error") {
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(-32000);
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("upstream rpc error")
            .to_string();
        return Err(OcwpError::new(code as i32, message));
    }
    parsed.get("result").cloned().ok_or_else(|| OcwpError::internal("rpc response missing result"))
}

/// Broadcast a signed raw transaction (used by `oc_send_transaction` after
/// consent + policy + enclave signing).
pub(super) fn broadcast_raw(
    chain_registry: &ChainRegistry,
    config: &oc_core::Config,
    chain_id: &str,
    signed_tx_hex: &str,
) -> Result<String, OcwpError> {
    let rpc_url = chain_registry.rpc_url(chain_id, config).ok_or_else(|| {
        OcwpError::invalid_params(format!("no RPC endpoint for chain '{chain_id}'"))
    })?;
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendRawTransaction",
        "params": [format!("0x{signed_tx_hex}")],
    })
    .to_string();
    let response_text = crate::shared_runtime()
        .block_on(async {
            let client = hpx::Client::new();
            let resp = client
                .post(&rpc_url)
                .header("Content-Type", "application/json")
                .body(body)
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .map_err(|e| format!("broadcast failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("broadcast endpoint returned {}", resp.status()));
            }
            resp.text().await.map_err(|e| format!("broadcast read failed: {e}"))
        })
        .map_err(|e| {
            tracing::warn!(error = %e, "ocwp: broadcast failed");
            OcwpError::internal("broadcast endpoint unreachable")
        })?;
    let parsed: Value = serde_json::from_str(&response_text)
        .map_err(|_| OcwpError::internal("broadcast endpoint returned malformed JSON"))?;
    if let Some(error) = parsed.get("error") {
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(-32000);
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("broadcast rejected")
            .to_string();
        return Err(OcwpError::new(code as i32, message));
    }
    parsed
        .get("result")
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| OcwpError::internal("broadcast response missing result"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_excludes_broadcast() {
        assert!(RPC_ALLOWLIST.contains(&"eth_call"));
        assert!(RPC_ALLOWLIST.contains(&"eth_getBalance"));
        assert!(!RPC_ALLOWLIST.contains(&"eth_sendRawTransaction"));
    }

    #[test]
    fn rate_limiter_allows_burst_then_throttles() {
        let limiter = RpcRateLimiter::new(30.0, 3.0);
        assert!(limiter.check("origin-a"));
        assert!(limiter.check("origin-a"));
        assert!(limiter.check("origin-a"));
        assert!(!limiter.check("origin-a"), "burst exhausted must throttle");
        // A different origin has its own bucket.
        assert!(limiter.check("origin-b"));
    }

    #[test]
    fn rate_limiter_bucket_keys_cannot_be_confused_by_the_client() {
        // Both halves of the bucket key are client-supplied. A length-prefixed
        // key means ("ab","c") and ("a","bc") stay in separate buckets: with a
        // plain concatenation they would collide and share one budget, which
        // is a denial of service against the other dApp on the same session.
        let limiter = RpcRateLimiter::new(30.0, 1.0);
        assert!(limiter.check("ab|c"));
        assert!(!limiter.check("ab|c"), "first bucket is now exhausted");
        assert!(limiter.check("a|bc"), "the other bucket is untouched");
    }

    #[test]
    fn rate_buckets_charge_both_the_session_and_the_extension() {
        // §3.4: a call is charged to BOTH the extension bucket and the session
        // bucket. Rate 1/s with burst 1 makes each bucket hold exactly one
        // token, so a single call spends both and the second is refused until
        // the refill — far longer than a test takes.
        let limiter = RpcRateLimiter::new(1.0, 1.0);
        let a = RateBuckets::new("chrome-extension://a", "session-1", &limiter);
        assert!(a.charge(), "both buckets start with a token");
        // One call consumed both the extension's and the session's token.
        assert!(!a.charge(), "extension bucket is empty");
        // A second session on the SAME extension shares the extension budget,
        // so it is throttled even though its own session bucket is untouched.
        let b = RateBuckets::new("chrome-extension://a", "session-2", &limiter);
        assert!(!b.charge(), "another session shares the extension budget");
        // A different extension is unaffected.
        let c = RateBuckets::new("chrome-extension://b", "session-3", &limiter);
        assert!(c.charge(), "a different extension is unaffected");

        // A rejected charge must not consume a token, or a caller could drain
        // someone else's budget simply by issuing calls it knows will fail.
        let limiter = RpcRateLimiter::new(1.0, 1.0);
        let e = RateBuckets::new("chrome-extension://a", "session-1", &limiter);
        assert!(e.charge());
        assert!(!e.charge());
        assert!(!e.charge(), "still exhausted, and nothing was consumed");
    }

    #[test]
    fn proxy_rejects_non_allowlisted_method_before_network() {
        let dir = tempfile::tempdir().unwrap();
        let registry = ChainRegistry::open(dir.path());
        let limiter = RpcRateLimiter::new(30.0, 60.0);
        let buckets = RateBuckets::new("https://dapp.example", "session", &limiter);
        let err = proxy(
            &registry,
            &oc_core::Config::default(),
            &buckets,
            "eip155:1",
            "eth_sendRawTransaction",
            &json!([]),
        )
        .expect_err("broadcast must not be proxied");
        assert_eq!(err.code, super::super::errors::CODE_UNSUPPORTED);
    }
}
