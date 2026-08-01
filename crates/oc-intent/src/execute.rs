use oc_core::ChainIdExt;

use crate::{
    build_call_data,
    error::IntentError,
    rpc::RpcClient,
    schema::{Intent, IntentKind, IntentResult, IntentStatus},
};

/// Execute a confirmed intent.
///
/// `signer` is a sync closure invoked with `(wallet_id, unsigned_tx_bytes)`
/// that must return the signed RLP-encoded transaction bytes. The closure is
/// sync because the Key-Agent UDS channel is itself sync (`std::os::unix::net`
/// + `std::thread`, per R55) — keeping oc-intent free of `async_trait` and `tokio`-in-signature
///   preserves R56's isolation invariant for the signing boundary even though oc-intent's RPC
///   client is async.
///
/// The wallet id is sourced from `intent.session_key_id` (the closest
/// available identifier on `Intent` for selecting the signing key).
pub async fn execute_intent<F>(
    intent: &Intent,
    rpc: &dyn RpcClient,
    signer: F,
) -> Result<IntentResult, IntentError>
where
    F: Fn(&str, &[u8]) -> Result<Vec<u8>, IntentError> + Send,
{
    if intent.is_expired() {
        return Ok(IntentResult {
            intent_id: intent.id,
            status: IntentStatus::Expired,
            tx_hash: None,
            receipt: None,
            error: Some("intent expired".to_string()),
        });
    }

    let tx_bytes = match &intent.kind {
        IntentKind::SignTransaction { tx_hex, .. } => hex::decode(tx_hex.trim_start_matches("0x"))
            .map_err(|e| IntentError::InvalidInput(format!("invalid tx_hex: {e}")))?,
        IntentKind::Pay { .. } | IntentKind::CrossChainTransfer { .. } => {
            let chain_num = parse_chain_id(&intent.chain_id)?;
            let call = build_call_data(&intent.kind, rpc.chain_id())?;
            // M8: surface RPC failures instead of silently falling back to
            // 21_000 gas / 1 gwei gas price — those defaults can mask a
            // misconfigured node and produce under-priced transactions.
            let gas_limit = rpc.estimate_gas(&call).await.map_err(IntentError::Rpc)?;
            let gas_price = rpc.gas_price().await.map_err(IntentError::Rpc)?;
            build_unsigned_eip1559_tx(
                chain_num,
                &call.to,
                &call.value,
                call.data.as_deref(),
                gas_limit,
                gas_price,
            )?
        }
        IntentKind::SignMessage { .. } => {
            // C3: SignMessage intents are not broadcastable — return Err
            // instead of Ok(Failed) so callers can distinguish "never
            // attempted" from "attempted and reverted".
            return Err(IntentError::Execution(
                "SignMessage intents are not broadcastable transactions".to_string(),
            ));
        }
    };

    // C2: sign the unsigned tx before broadcasting. The signer is injected
    // by the CLI layer (which calls the Key-Agent over UDS); oc-intent itself
    // never touches private keys.
    let signed_tx_bytes = signer(intent.session_key_id.as_str(), &tx_bytes)
        .map_err(|e| IntentError::Execution(format!("signing failed: {e}")))?;

    // C3: broadcast failure is an Err, not Ok(Failed).
    let tx_hash = rpc
        .send_raw_transaction(&signed_tx_bytes)
        .await
        .map_err(|e| IntentError::Execution(format!("broadcast failed: {e}")))?;

    // C3: receipt failure is an Err. We include the tx_hash in the message so
    // callers can still recover it (the tx was broadcast but not yet mined).
    let receipt = rpc.wait_for_receipt(&tx_hash).await.map(Some).map_err(|e| {
        IntentError::Execution(format!("receipt wait failed for tx {tx_hash}: {e}"))
    })?;

    Ok(IntentResult {
        intent_id: intent.id,
        status: IntentStatus::Confirmed,
        tx_hash: Some(tx_hash),
        receipt,
        error: None,
    })
}

/// Parse a CAIP-2 chain ID (e.g. "eip155:8453") to its numeric EVM value.
///
/// H9: returns `Result` instead of `unwrap_or(1)`. Silently falling back to
/// chain id 1 (Ethereum mainnet) on a malformed input would broadcast the
/// transaction on the wrong chain — a critical safety violation. Uses the
/// type-safe `oc_core::ChainId` parser and its `evm_chain_id()` helper.
fn parse_chain_id(chain_id: &str) -> Result<u64, IntentError> {
    let parsed: oc_core::ChainId = chain_id
        .parse()
        .map_err(|e| IntentError::InvalidChain(format!("not a CAIP-2 id: {chain_id}: {e}")))?;
    parsed
        .evm_chain_id()
        .ok_or_else(|| IntentError::InvalidChain(format!("not a numeric EVM chain id: {chain_id}")))
}

// `build_call_data` is now shared in `lib.rs` — used by both simulate and execute.

/// Minimal unsigned EIP-1559 transaction RLP. ponytail: manual RLP, add oc-signer dep if signing
/// lands here.
fn build_unsigned_eip1559_tx(
    chain_id: u64,
    to: &str,
    value: &Option<String>,
    data: Option<&[u8]>,
    gas_limit: u64,
    gas_price: u64,
) -> Result<Vec<u8>, IntentError> {
    let to_bytes = hex::decode(to.trim_start_matches("0x"))
        .map_err(|e| IntentError::InvalidInput(format!("invalid recipient: {e}")))?;
    let value_bytes = value
        .as_deref()
        .and_then(|v| hex::decode(v.trim_start_matches("0x")).ok())
        .unwrap_or_default();
    let data_bytes = data.unwrap_or(&[]);
    let max_fee = gas_price.saturating_mul(2);
    let max_priority = 1_000_000_000u64; // 1 gwei

    let items: Vec<Vec<u8>> = vec![
        rlp_u64(chain_id),
        rlp_u64(0), // nonce
        rlp_u64(max_priority),
        rlp_u64(max_fee),
        rlp_u64(gas_limit),
        rlp_bytes(&to_bytes),
        rlp_bytes(&value_bytes),
        rlp_bytes(data_bytes),
        rlp_list(&[]), // access list
    ];

    let mut payload = vec![0x02]; // EIP-1559 tx type
    payload.extend_from_slice(&rlp_list(&items));
    Ok(payload)
}

fn rlp_u64(val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![0x80]; // RLP empty string
    }
    let be = val.to_be_bytes();
    let trimmed = &be[be.iter().position(|&b| b != 0).unwrap_or(7)..];
    rlp_bytes(trimmed)
}

fn rlp_bytes(data: &[u8]) -> Vec<u8> {
    match data.len() {
        1 if data[0] < 0x80 => data.to_vec(),
        len @ 0..=55 => {
            let mut out = vec![0x80 + len as u8];
            out.extend_from_slice(data);
            out
        }
        len => {
            let len_bytes = len.to_be_bytes();
            let trimmed = &len_bytes[len_bytes.iter().position(|&b| b != 0).unwrap_or(7)..];
            let mut out = vec![0xb7 + trimmed.len() as u8];
            out.extend_from_slice(trimmed);
            out.extend_from_slice(data);
            out
        }
    }
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    if body.len() <= 55 {
        let mut out = vec![0xc0 + body.len() as u8];
        out.extend_from_slice(&body);
        out
    } else {
        let len_bytes = body.len().to_be_bytes();
        let trimmed = &len_bytes[len_bytes.iter().position(|&b| b != 0).unwrap_or(7)..];
        let mut out = vec![0xf7 + trimmed.len() as u8];
        out.extend_from_slice(trimmed);
        out.extend_from_slice(&body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        rpc::MockRpcClient,
        schema::{Intent, IntentKind},
    };

    fn make_pay_intent() -> Intent {
        Intent::new(
            IntentKind::Pay {
                amount: "10.5 USDC".to_string(),
                recipient: "0xabcabcabcabcabcabcabcabcabcabcabca".to_string(),
                token: None,
            },
            "eip155:8453".to_string(),
            "sk-test".to_string(),
        )
    }

    /// Test signer that returns the unsigned bytes unchanged — sufficient for
    /// MockRpcClient which doesn't validate signatures.
    fn identity_signer() -> impl Fn(&str, &[u8]) -> Result<Vec<u8>, IntentError> {
        |_wallet_id: &str, tx_bytes: &[u8]| Ok(tx_bytes.to_vec())
    }

    #[tokio::test]
    async fn execute_returns_confirmed_for_valid_intent() {
        let intent = make_pay_intent();
        let rpc = MockRpcClient::new("eip155:8453");
        let result = execute_intent(&intent, &rpc, identity_signer()).await.expect("execute");
        assert_eq!(result.status, IntentStatus::Confirmed);
        assert!(result.tx_hash.is_some());
        assert!(result.receipt.is_some());
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn execute_returns_expired_for_past_intent() {
        let mut intent = make_pay_intent();
        intent.expires_at = intent.created_at - 1;
        let rpc = MockRpcClient::new("eip155:8453");
        let result = execute_intent(&intent, &rpc, identity_signer()).await.expect("execute");
        assert_eq!(result.status, IntentStatus::Expired);
        assert!(result.tx_hash.is_none());
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn execute_returns_err_when_signer_fails() {
        // C2 regression: a signer failure must propagate as Err, not be
        // swallowed and broadcast as an unsigned transaction.
        let intent = make_pay_intent();
        let rpc = MockRpcClient::new("eip155:8453");
        let failing_signer =
            |_: &str, _: &[u8]| Err(IntentError::Execution("key-agent unavailable".to_string()));
        let err = execute_intent(&intent, &rpc, failing_signer).await.expect_err("must error");
        assert!(
            err.to_string().contains("signing failed"),
            "expected signing-failed wrapper, got: {err}"
        );
        assert!(
            err.to_string().contains("key-agent unavailable"),
            "expected inner signer error preserved, got: {err}"
        );
    }

    #[tokio::test]
    async fn execute_returns_err_for_sign_message_intent() {
        // C3 regression: SignMessage is not broadcastable — must be Err, not
        // Ok(Failed).
        let intent = Intent::new(
            IntentKind::SignMessage {
                message: "hello".to_string(),
                encoding: crate::schema::MessageEncoding::Utf8,
            },
            "eip155:1".to_string(),
            "sk-test".to_string(),
        );
        let rpc = MockRpcClient::new("eip155:1");
        let err = execute_intent(&intent, &rpc, identity_signer()).await.expect_err("must error");
        assert!(err.to_string().contains("SignMessage"));
    }

    #[tokio::test]
    async fn execute_returns_err_for_invalid_chain_id() {
        // H9 regression: a non-CAIP-2 chain id must error, not fall back to 1.
        let intent = Intent::new(
            IntentKind::Pay {
                amount: "1 USDC".to_string(),
                recipient: "0xabcabcabcabcabcabcabcabcabcabcabca".to_string(),
                token: None,
            },
            "not-a-caip2-id".to_string(),
            "sk-test".to_string(),
        );
        let rpc = MockRpcClient::new("not-a-caip2-id");
        let err = execute_intent(&intent, &rpc, identity_signer()).await.expect_err("must error");
        assert!(matches!(err, IntentError::InvalidChain(_)), "got: {err}");
    }

    #[test]
    fn parse_chain_id_returns_numeric_for_eip155() {
        assert_eq!(parse_chain_id("eip155:1").unwrap(), 1);
        assert_eq!(parse_chain_id("eip155:8453").unwrap(), 8453);
        assert_eq!(parse_chain_id("eip155:42161").unwrap(), 42161);
    }

    #[test]
    fn parse_chain_id_errors_on_non_caip2_input() {
        assert!(parse_chain_id("garbage").is_err());
        assert!(parse_chain_id("eip155").is_err());
    }

    #[test]
    fn parse_chain_id_errors_on_non_evm_namespace() {
        // Solana is a valid CAIP-2 id but not an EVM chain.
        assert!(parse_chain_id("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp").is_err());
    }
}
