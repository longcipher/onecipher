use crate::{
    error::IntentError,
    rpc::RpcClient,
    schema::{Intent, IntentResult, IntentStatus},
};

/// Execute a confirmed intent.
pub async fn execute_intent(
    intent: &Intent,
    rpc: &dyn RpcClient,
) -> Result<IntentResult, IntentError> {
    // 1. Check not expired
    if intent.is_expired() {
        return Ok(IntentResult {
            intent_id: intent.id,
            status: IntentStatus::Expired,
            tx_hash: None,
            receipt: None,
            error: Some("intent expired".to_string()),
        });
    }

    // 2. Sign + broadcast. Real signing requires Key-Agent RPC integration (oc-signing-core is not
    //    yet wired into this layer — see Stage 3 TODO in docs/design.md §7). For now we use
    //    placeholder bytes; a real RPC client (HpxRpcClient) will reject them with a
    //    server/transport error, which is surfaced in the IntentResult.error field below.
    // TODO(stage-3): replace placeholder with bytes signed via Key-Agent RPC.
    let placeholder_tx_bytes = vec![0u8; 32];

    // 3. Send the transaction
    let tx_hash = match rpc.send_raw_transaction(&placeholder_tx_bytes).await {
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
                recipient: "0xabc".to_string(),
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
