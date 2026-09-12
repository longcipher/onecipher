//! Intent hot-path adapter (WC / HTTP-RPC / wallet-rpc).
//!
//! The Intent Layer (`simulate_intent` / `execute_intent`) was CLI-only. This
//! module is the SOLE bridge onto the production hot paths. Design rules:
//!
//! - **C13 trait boundary:** the hot path NEVER touches `HardenedBytes` or any private key. Signing
//!   goes through [`IntentSigner`], whose production implementation forwards to the Key-Agent over
//!   UDS (the Key-Agent owns all key material). The intent code only sees opaque `&[u8]` in /
//!   signed bytes out.
//! - **Fail-closed RPC selection:** [`select_rpc_client`] requires an explicit `rpc_url` (param or
//!   `OC_RPC_URL` env). Without one it returns an error — the hot path MUST NOT silently fall back
//!   to `MockRpcClient` (which would simulate fake gas and broadcast to a black hole).
//! - **CrossChainTransfer stays fail-closed:** `build_call_data` rejects it with `Unsupported` (no
//!   bridge integration yet). This module documents and re-exports that behavior; it does NOT add a
//!   bypass.

use crate::intent::{
    Intent, IntentError, IntentResult, IntentSummary, SigningKeyRef, execute_intent,
    rpc::{MockRpcClient, RpcClient},
    simulate_intent,
};

/// C13 signing boundary for hot-path intent execution.
///
/// Implementations receive the resolved [`SigningKeyRef`] plus the unsigned
/// transaction bytes and return the signed (RLP-encoded) transaction bytes.
/// Production implementations forward to the Key-Agent over UDS; tests use an
/// identity closure. No key material crosses this trait.
pub trait IntentSigner: Send + Sync {
    /// Sign `unsigned_tx` for `key_ref`.
    fn sign(&self, key_ref: &SigningKeyRef, unsigned_tx: &[u8]) -> Result<Vec<u8>, IntentError>;
}

impl<F> IntentSigner for F
where
    F: Fn(&SigningKeyRef, &[u8]) -> Result<Vec<u8>, IntentError> + Send + Sync,
{
    fn sign(&self, key_ref: &SigningKeyRef, unsigned_tx: &[u8]) -> Result<Vec<u8>, IntentError> {
        self(key_ref, unsigned_tx)
    }
}

/// Hot-path RPC configuration.
#[derive(Debug, Clone, Default)]
pub struct HotPathConfig {
    /// EVM JSON-RPC endpoint. `None` falls back to `OC_RPC_URL` env.
    pub rpc_url: Option<String>,
    /// Explicit opt-in to the test mock (unit tests only — never set in
    /// production; the hot path fails closed without a real URL).
    pub allow_mock: bool,
}

impl HotPathConfig {
    /// Build from explicit values.
    pub fn new(rpc_url: Option<String>) -> Self {
        Self { rpc_url, allow_mock: false }
    }

    /// Effective RPC URL: explicit value, else `OC_RPC_URL` env.
    pub fn effective_rpc_url(&self) -> Option<String> {
        self.rpc_url
            .clone()
            .or_else(|| std::env::var("OC_RPC_URL").ok().filter(|v| !v.trim().is_empty()))
    }
}

/// Select an RPC client for the hot path (fail-closed).
///
/// Returns a real [`crate::HpxRpcClient`] when an RPC URL is configured.
/// Returns an error when no URL is available — the hot path MUST NOT use the
/// mock (fake gas / fake receipts). Tests opt in via
/// `HotPathConfig { allow_mock: true }`.
pub fn select_rpc_client(
    chain_id: &str,
    config: &HotPathConfig,
) -> Result<Box<dyn RpcClient>, IntentError> {
    if let Some(url) = config.effective_rpc_url() {
        let client = crate::HpxRpcClient::new(chain_id, url)
            .map_err(|e| IntentError::Rpc(crate::intent::RpcError::Transport(e.to_string())))?;
        return Ok(Box::new(client));
    }
    if config.allow_mock {
        return Ok(Box::new(MockRpcClient::new(chain_id)));
    }
    Err(IntentError::InvalidInput(
        "no RPC endpoint configured (pass rpc_url or set OC_RPC_URL); refusing to simulate/execute against a mock on the hot path"
            .to_string(),
    ))
}

/// Simulate an intent on the hot path (read-only, no signer needed).
pub async fn simulate_for_hot_path(
    intent: &Intent,
    rpc: &dyn RpcClient,
) -> Result<IntentSummary, IntentError> {
    simulate_intent(intent, rpc).await
}

/// Execute a confirmed intent on the hot path via a C13 [`IntentSigner`].
///
/// `from_address` is required so the pending nonce is fetched (M-04a).
/// `CrossChainTransfer` intents fail closed with `Unsupported` before
/// anything is signed (bridge integration pending — see module docs).
pub async fn execute_for_hot_path<S>(
    intent: &Intent,
    rpc: &dyn RpcClient,
    from_address: &str,
    signer: &S,
) -> Result<IntentResult, IntentError>
where
    S: IntentSigner,
{
    execute_intent(intent, rpc, from_address, |key_ref, tx_bytes| signer.sign(key_ref, tx_bytes))
        .await
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use crate::intent::{IntentKind, schema::MessageEncoding};

    fn pay_intent() -> Intent {
        Intent::new(
            IntentKind::Pay {
                amount: "0x0de0b6b3a7640000".to_string(),
                recipient: "0xabcabcabcabcabcabcabcabcabcabcabca".to_string(),
                token: None,
            },
            "eip155:8453".to_string(),
            "sk-test".to_string(),
        )
    }

    #[test]
    fn select_rpc_client_fails_closed_without_url() {
        let cfg = HotPathConfig::new(None);
        // OC_RPC_URL may be set in the dev environment — clear it for this
        // assertion via a scoped remove (restored afterwards).
        let saved = std::env::var("OC_RPC_URL").ok();
        unsafe { std::env::remove_var("OC_RPC_URL") };
        let err = match select_rpc_client("eip155:8453", &cfg) {
            Ok(_) => panic!("must fail closed without a URL"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("no RPC endpoint"), "got: {err}");
        if let Some(v) = saved {
            unsafe { std::env::set_var("OC_RPC_URL", v) };
        }
    }

    #[test]
    fn select_rpc_client_allows_mock_only_when_opted_in() {
        let saved = std::env::var("OC_RPC_URL").ok();
        unsafe { std::env::remove_var("OC_RPC_URL") };
        let cfg = HotPathConfig { rpc_url: None, allow_mock: true };
        let client = select_rpc_client("eip155:8453", &cfg).expect("mock allowed");
        assert_eq!(client.chain_id(), "eip155:8453");
        if let Some(v) = saved {
            unsafe { std::env::set_var("OC_RPC_URL", v) };
        }
    }

    #[tokio::test]
    async fn hot_path_simulate_matches_direct_simulate() {
        let intent = pay_intent();
        let rpc = MockRpcClient::new("eip155:8453");
        let via_hot = simulate_for_hot_path(&intent, &rpc).await.expect("simulate");
        let direct = simulate_intent(&intent, &rpc).await.expect("direct");
        assert_eq!(via_hot.human_readable, direct.human_readable);
    }

    #[tokio::test]
    async fn hot_path_execute_uses_c13_signer_boundary() {
        // The signer sees only opaque bytes; HardenedBytes never crosses.
        let intent = pay_intent();
        let rpc = MockRpcClient::new("eip155:8453").with_nonce(3);
        let signer = |_key: &SigningKeyRef, tx: &[u8]| Ok(tx.to_vec());
        let result = execute_for_hot_path(
            &intent,
            &rpc,
            "0x1111111111111111111111111111111111111111",
            &signer,
        )
        .await
        .expect("execute");
        assert_eq!(result.status, crate::intent::IntentStatus::Confirmed);
    }

    #[tokio::test]
    async fn hot_path_cross_chain_transfer_fails_closed() {
        let intent = Intent::new(
            IntentKind::CrossChainTransfer {
                amount: "100 USDC".to_string(),
                asset: "eip155:8453/erc20:0x1".to_string(),
                from_chain: "eip155:8453".to_string(),
                to_chain: "eip155:42161".to_string(),
                recipient: "0xabcabcabcabcabcabcabcabcabcabcabca".to_string(),
            },
            "eip155:8453".to_string(),
            "sk-test".to_string(),
        );
        let rpc = MockRpcClient::new("eip155:8453");
        let signer = |_key: &SigningKeyRef, tx: &[u8]| Ok(tx.to_vec());
        let err = execute_for_hot_path(
            &intent,
            &rpc,
            "0x1111111111111111111111111111111111111111",
            &signer,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IntentError::Unsupported(_)), "got: {err}");
    }

    #[tokio::test]
    async fn hot_path_sign_message_is_not_broadcastable() {
        let intent = Intent::new(
            IntentKind::SignMessage {
                message: "hello".to_string(),
                encoding: MessageEncoding::Utf8,
            },
            "eip155:1".to_string(),
            "sk-test".to_string(),
        );
        let rpc = MockRpcClient::new("eip155:1");
        let signer = |_key: &SigningKeyRef, tx: &[u8]| Ok(tx.to_vec());
        let err = execute_for_hot_path(&intent, &rpc, "0xabc", &signer).await.unwrap_err();
        assert!(err.to_string().contains("SignMessage"));
    }
}
