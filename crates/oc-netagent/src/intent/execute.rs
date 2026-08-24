use oc_core::ChainIdExt;

use super::{
    build_call_data,
    error::IntentError,
    rpc::RpcClient,
    schema::{Intent, IntentKind, IntentResult, IntentStatus, SigningKeyRef},
};

/// Execute a confirmed intent.
///
/// `from_address` is the sender's EVM address; it is required so the real
/// pending nonce can be fetched via `eth_getTransactionCount` before building
/// the transaction (M-04a). A hard-coded nonce of 0 made every executed
/// intent after the first revert on-chain.
///
/// `signer` is a sync closure invoked with `(key_ref, unsigned_tx_bytes)`
/// that must return the signed RLP-encoded transaction bytes. The closure is
/// sync because the Key-Agent UDS channel is itself sync (`std::os::unix::net`
/// + `std::thread`, per R55) — keeping oc-intent free of `async_trait` and `tokio`-in-signature
///   preserves R56's isolation invariant for the signing boundary even though oc-intent's RPC
///   client is async.
///
/// The signing key reference is resolved from `intent.session_key_id` (the
/// closest available identifier on `Intent` for selecting the signing key).
/// `SigningKeyRef` makes the resolution boundary explicit: the CLI layer maps
/// the session key id to a concrete wallet/HD key before invoking the signer,
/// so this function never silently conflates the two identifiers.
pub async fn execute_intent<F>(
    intent: &Intent,
    rpc: &dyn RpcClient,
    from_address: &str,
    signer: F,
) -> Result<IntentResult, IntentError>
where
    F: Fn(&SigningKeyRef, &[u8]) -> Result<Vec<u8>, IntentError> + Send,
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
        // CrossChainTransfer is included so `build_call_data`'s fail-closed
        // Unsupported error (M-04b) fires before anything is signed.
        IntentKind::Pay { .. } | IntentKind::CrossChainTransfer { .. } => {
            let chain_num = parse_chain_id(&intent.chain_id)?;
            let call = build_call_data(&intent.kind, rpc.chain_id())?;
            if from_address.trim().is_empty() {
                return Err(IntentError::InvalidInput(
                    "sender address is required to fetch the transaction nonce".to_string(),
                ));
            }
            // M-04a: fetch the real pending nonce for the sender instead of
            // hard-coding 0.
            let nonce = rpc.transaction_count(from_address).await.map_err(IntentError::Rpc)?;
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
                nonce,
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
    // never touches private keys. The session key id is resolved to a
    // `SigningKeyRef` so the caller's mapping is explicit.
    let key_ref = SigningKeyRef::from(intent.session_key_id.as_str());
    let signed_tx_bytes = signer(&key_ref, &tx_bytes)
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

// `build_call_data` is now shared in `mod.rs` — used by both simulate and execute.

/// Minimal unsigned EIP-1559 transaction RLP.
///
/// Reuses `oc_signer::rlp` (the same encoder used by the WalletSigner surface
/// in `wallet_rpc.rs`) so there is a single RLP implementation across the
/// workspace instead of two hand-rolled copies.
///
/// A non-hex `value` (e.g. a human-readable `"10.5 USDC"` that bypassed
/// `parse_amount`) is rejected rather than silently encoded as `0` wei — a
/// silent zero-value transaction is a critical safety failure.
fn build_unsigned_eip1559_tx(
    chain_id: u64,
    to: &str,
    value: &Option<String>,
    data: Option<&[u8]>,
    gas_limit: u64,
    gas_price: u64,
    nonce: u64,
) -> Result<Vec<u8>, IntentError> {
    use oc_signer::rlp::{encode_bytes, encode_list, encode_u64};

    let to_bytes = hex::decode(to.trim_start_matches("0x"))
        .map_err(|e| IntentError::InvalidInput(format!("invalid recipient: {e}")))?;
    // Canonical EVM hex QUANTITIES omit leading zeros (e.g. 1 wei is "0x1"),
    // which yields an odd digit count; pad to a whole byte before decoding
    // instead of rejecting the canonical form.
    let decode_quantity = |s: &str| -> Result<Vec<u8>, IntentError> {
        let digits = s.trim_start_matches("0x");
        let padded = if digits.len() % 2 == 1 { format!("0{digits}") } else { digits.to_string() };
        hex::decode(&padded)
            .map_err(|e| IntentError::InvalidInput(format!("invalid hex quantity '{s}': {e}")))
    };
    let value_bytes = match value.as_deref() {
        Some(v) => decode_quantity(v).map_err(|e| {
            IntentError::InvalidInput(format!("invalid value (must be hex wei): {e}"))
        })?,
        None => Vec::new(),
    };
    let data_bytes = data.unwrap_or(&[]);
    let max_fee = gas_price.saturating_mul(2);
    let max_priority = 1_000_000_000u64; // 1 gwei

    let items: Vec<u8> = [
        encode_u64(chain_id),
        encode_u64(nonce), // M-04a: real pending nonce, not a hard-coded 0
        encode_u64(max_priority),
        encode_u64(max_fee),
        encode_u64(gas_limit),
        encode_bytes(&to_bytes),
        encode_bytes(&value_bytes),
        encode_bytes(data_bytes),
        encode_list(&[]), // access list
    ]
    .concat();

    let mut payload = vec![0x02]; // EIP-1559 tx type
    payload.extend_from_slice(&encode_list(&items));
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        super::{
            rpc::MockRpcClient,
            schema::{Intent, IntentKind, MessageEncoding},
        },
        *,
    };

    /// Sender address used by tests (the mock ignores its value).
    const TEST_FROM: &str = "0x1111111111111111111111111111111111111111";

    fn make_pay_intent() -> Intent {
        Intent::new(
            IntentKind::Pay {
                // Native amount must be a hex wei string once it reaches the
                // on-chain builder — `build_unsigned_eip1559_tx` rejects
                // non-hex values rather than silently encoding 0 wei.
                amount: "0x0de0b6b3a7640000".to_string(),
                recipient: "0xabcabcabcabcabcabcabcabcabcabcabca".to_string(),
                token: None,
            },
            "eip155:8453".to_string(),
            "sk-test".to_string(),
        )
    }

    /// Test signer that returns the unsigned bytes unchanged — sufficient for
    /// MockRpcClient which doesn't validate signatures.
    fn identity_signer() -> impl Fn(&SigningKeyRef, &[u8]) -> Result<Vec<u8>, IntentError> {
        |_key: &SigningKeyRef, tx_bytes: &[u8]| Ok(tx_bytes.to_vec())
    }

    #[tokio::test]
    async fn execute_returns_confirmed_for_valid_intent() {
        let intent = make_pay_intent();
        let rpc = MockRpcClient::new("eip155:8453");
        let result =
            execute_intent(&intent, &rpc, TEST_FROM, identity_signer()).await.expect("execute");
        assert_eq!(result.status, IntentStatus::Confirmed);
        assert!(result.tx_hash.is_some());
        assert!(result.receipt.is_some());
        assert!(result.error.is_none());
        // M-04a: the nonce lookup must happen on every execution.
        assert_eq!(rpc.transaction_count_calls(), 1);
    }

    #[tokio::test]
    async fn execute_fetches_nonce_and_encodes_it() {
        // M-04a regression: the pending nonce from eth_getTransactionCount
        // must be encoded into the unsigned transaction (never a hard-coded
        // 0).
        let intent = make_pay_intent();
        let rpc = MockRpcClient::new("eip155:8453").with_nonce(7);
        let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let sink = Arc::clone(&captured);
        let signer = move |_key: &SigningKeyRef, tx_bytes: &[u8]| {
            *sink.lock().unwrap() = Some(tx_bytes.to_vec());
            Ok(tx_bytes.to_vec())
        };
        execute_intent(&intent, &rpc, TEST_FROM, signer).await.expect("execute");

        assert_eq!(rpc.transaction_count_calls(), 1, "nonce must be fetched via RPC");
        let tx = captured.lock().unwrap().clone().expect("signer captured tx bytes");
        // Layout: type byte, RLP list header, then items starting with
        // chain_id (8453 → minimal BE [0x21, 0x05]) followed by the nonce
        // (7 → [0x07]).
        let pos = tx.windows(2).position(|w| w == [0x21, 0x05]).expect("chain id bytes in tx");
        assert_eq!(tx[pos + 2], 0x07, "nonce 7 must be encoded right after chain id");
    }

    #[tokio::test]
    async fn execute_rejects_missing_sender_address() {
        // Fail closed: without a sender address the nonce cannot be fetched,
        // so execution must error instead of silently building a nonce-0 tx.
        let intent = make_pay_intent();
        let rpc = MockRpcClient::new("eip155:8453");
        let err = execute_intent(&intent, &rpc, "", identity_signer())
            .await
            .expect_err("empty sender must error");
        assert!(matches!(err, IntentError::InvalidInput(_)), "got {err}");
        assert_eq!(rpc.transaction_count_calls(), 0, "no nonce lookup without an address");
        assert_eq!(rpc.send_raw_transaction_calls(), 0, "nothing may be broadcast");
    }

    #[tokio::test]
    async fn execute_never_signs_cross_chain_transfer() {
        // M-04b regression: CrossChainTransfer must fail closed with
        // Unsupported — no signing, no broadcast.
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
        let signed: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let flag = Arc::clone(&signed);
        let signer = move |_key: &SigningKeyRef, tx_bytes: &[u8]| {
            *flag.lock().unwrap() = true;
            Ok(tx_bytes.to_vec())
        };
        let err = execute_intent(&intent, &rpc, TEST_FROM, signer)
            .await
            .expect_err("cross-chain transfer must be unsupported");
        assert!(matches!(err, IntentError::Unsupported(_)), "got {err}");
        assert!(!*signed.lock().unwrap(), "nothing may be signed");
        assert_eq!(rpc.send_raw_transaction_calls(), 0, "nothing may be broadcast");
    }

    #[tokio::test]
    async fn execute_returns_expired_for_past_intent() {
        let mut intent = make_pay_intent();
        intent.expires_at = intent.created_at - 1;
        let rpc = MockRpcClient::new("eip155:8453");
        let result =
            execute_intent(&intent, &rpc, TEST_FROM, identity_signer()).await.expect("execute");
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
        let failing_signer = |_: &SigningKeyRef, _: &[u8]| {
            Err(IntentError::Execution("key-agent unavailable".to_string()))
        };
        let err =
            execute_intent(&intent, &rpc, TEST_FROM, failing_signer).await.expect_err("must error");
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
                encoding: MessageEncoding::Utf8,
            },
            "eip155:1".to_string(),
            "sk-test".to_string(),
        );
        let rpc = MockRpcClient::new("eip155:1");
        let err = execute_intent(&intent, &rpc, TEST_FROM, identity_signer())
            .await
            .expect_err("must error");
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
        let err = execute_intent(&intent, &rpc, TEST_FROM, identity_signer())
            .await
            .expect_err("must error");
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
