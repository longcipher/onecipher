use crate::{
    error::IntentError,
    rpc::{CallData, RpcClient},
    schema::{Intent, IntentKind, IntentResult, IntentStatus},
};

/// Execute a confirmed intent.
pub async fn execute_intent(
    intent: &Intent,
    rpc: &dyn RpcClient,
) -> Result<IntentResult, IntentError> {
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
        IntentKind::SignTransaction { tx_hex, .. } => {
            hex::decode(tx_hex.trim_start_matches("0x"))
                .map_err(|e| IntentError::InvalidInput(format!("invalid tx_hex: {e}")))?
        }
        IntentKind::Pay { .. }
        | IntentKind::CrossChainTransfer { .. } => {
            let chain_num = parse_chain_id(&intent.chain_id);
            let call = build_call_data(&intent.kind, rpc.chain_id())?;
            let gas_limit = rpc.estimate_gas(&call).await.unwrap_or(21_000);
            let gas_price = rpc.gas_price().await.unwrap_or(1_000_000_000);
            build_unsigned_eip1559_tx(chain_num, &call.to, &call.value, call.data.as_deref(), gas_limit, gas_price)?
        }
        IntentKind::SignMessage { .. } => {
            return Ok(IntentResult {
                intent_id: intent.id,
                status: IntentStatus::Failed,
                tx_hash: None,
                receipt: None,
                error: Some("SignMessage intents are not broadcastable transactions".to_string()),
            });
        }
    };

    let tx_hash = match rpc.send_raw_transaction(&tx_bytes).await {
        Ok(h) => h,
        Err(e) => {
            return Ok(IntentResult {
                intent_id: intent.id,
                status: IntentStatus::Failed,
                tx_hash: None,
                receipt: None,
                error: Some(format!("broadcast failed: {e}")),
            });
        }
    };

    // 4. Wait for receipt
    let receipt = match rpc.wait_for_receipt(&tx_hash).await {
        Ok(r) => Some(r),
        Err(e) => {
            return Ok(IntentResult {
                intent_id: intent.id,
                status: IntentStatus::Submitted,
                tx_hash: Some(tx_hash),
                receipt: None,
                error: Some(format!("receipt wait failed: {e}")),
            });
        }
    };

    Ok(IntentResult {
        intent_id: intent.id,
        status: IntentStatus::Confirmed,
        tx_hash: Some(tx_hash),
        receipt,
        error: None,
    })
}

/// Parse a CAIP-2 chain ID (e.g. "eip155:8453") to its numeric value.
fn parse_chain_id(chain_id: &str) -> u64 {
    chain_id
        .split(':')
        .next_back()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

fn build_call_data(kind: &IntentKind, _chain: &str) -> Result<CallData, IntentError> {
    match kind {
        IntentKind::Pay { recipient, .. } => Ok(CallData {
            from: None,
            to: recipient.clone(),
            value: Some("0x0".to_string()),
            data: None,
        }),
        IntentKind::CrossChainTransfer { recipient, .. } => Ok(CallData {
            from: None,
            to: recipient.clone(),
            value: Some("0x0".to_string()),
            data: None,
        }),
        _ => Err(IntentError::InvalidInput("unsupported intent kind for tx building".into())),
    }
}

/// Minimal unsigned EIP-1559 transaction RLP. ponytail: manual RLP, add oc-signer dep if signing lands here.
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
        rlp_u64(0),              // nonce
        rlp_u64(max_priority),
        rlp_u64(max_fee),
        rlp_u64(gas_limit),
        rlp_bytes(&to_bytes),
        rlp_bytes(&value_bytes),
        rlp_bytes(data_bytes),
        rlp_list(&[]),           // access list
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

    #[tokio::test]
    async fn execute_returns_confirmed_for_valid_intent() {
        let intent = make_pay_intent();
        let rpc = MockRpcClient::new("eip155:8453");
        let result = execute_intent(&intent, &rpc).await.expect("execute");
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
        let result = execute_intent(&intent, &rpc).await.expect("execute");
        assert_eq!(result.status, IntentStatus::Expired);
        assert!(result.tx_hash.is_none());
        assert!(result.error.is_some());
    }
}
