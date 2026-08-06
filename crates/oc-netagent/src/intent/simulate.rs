use super::{
    build_call_data,
    error::IntentError,
    rpc::RpcClient,
    schema::{Intent, IntentKind, IntentSummary},
};

/// Simulate an intent before execution.
pub async fn simulate_intent(
    intent: &Intent,
    rpc: &dyn RpcClient,
) -> Result<IntentSummary, IntentError> {
    // 1. Build call data from intent
    let call_data = build_call_data(&intent.kind, &intent.chain_id)?;

    // 2. Estimate gas
    let gas_estimate = rpc.estimate_gas(&call_data).await.map_err(IntentError::Rpc)?;

    // 3. Simulate the call
    let sim_result = rpc.eth_call(&call_data).await.map_err(IntentError::Rpc)?;

    // 4. Get gas price and calculate USD cost
    let gas_price = rpc.gas_price().await.map_err(IntentError::Rpc)?;
    let native_price = rpc.native_price_usd().await.map_err(IntentError::Rpc)?;

    let gas_cost_wei = u128::from(gas_estimate) * u128::from(gas_price);
    let gas_cost_usd = (gas_cost_wei as f64 / 1e18) * native_price;

    // 5. Get intent amount in USD
    let amount_usd = intent_amount_usd(intent);

    // 6. Generate warnings
    let mut warnings = Vec::new();
    if sim_result.is_null() && !matches!(intent.kind, IntentKind::SignMessage { .. }) {
        warnings.push("simulation returned null — contract may not exist".to_string());
    }
    if gas_cost_usd > 5.0 {
        warnings.push(format!("high gas cost: ${:.2}", gas_cost_usd));
    }

    // 7. Generate human-readable summary
    let human_readable = format_summary(intent, gas_cost_usd, amount_usd);

    Ok(IntentSummary {
        intent_id: intent.id,
        human_readable,
        gas_estimate_usd: gas_cost_usd,
        total_cost_usd: gas_cost_usd + amount_usd,
        warnings,
        simulation_tx_hash: None,
    })
}

fn intent_amount_usd(intent: &Intent) -> f64 {
    match &intent.kind {
        IntentKind::Pay { amount, .. } => {
            // Parse "10.5 USDC" → 10.5
            amount.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)
        }
        _ => 0.0,
    }
}

fn format_summary(intent: &Intent, gas_cost_usd: f64, amount_usd: f64) -> String {
    match &intent.kind {
        IntentKind::Pay { amount, recipient, .. } => {
            format!(
                "Send {} to {}... on {} (est. gas: ${:.4}, total: ${:.2})",
                amount,
                &recipient[..recipient.len().min(10)],
                intent.chain_id,
                gas_cost_usd,
                gas_cost_usd + amount_usd
            )
        }
        IntentKind::SignTransaction { .. } => {
            format!("Sign transaction on {} (est. gas: ${:.4})", intent.chain_id, gas_cost_usd)
        }
        IntentKind::SignMessage { .. } => {
            format!("Sign message on {}", intent.chain_id)
        }
        IntentKind::CrossChainTransfer { amount, from_chain, to_chain, recipient, .. } => {
            format!(
                "Transfer {} from {} to {} for {}... (est. gas: ${:.4})",
                amount,
                from_chain,
                to_chain,
                &recipient[..recipient.len().min(10)],
                gas_cost_usd
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            build_call_data,
            rpc::MockRpcClient,
            schema::{Intent, IntentKind, MessageEncoding},
        },
        *,
    };

    fn make_pay_intent() -> Intent {
        Intent::new(
            IntentKind::Pay {
                amount: "10.5 USDC".to_string(),
                recipient: "0xabcdef1234567890".to_string(),
                token: None,
            },
            "eip155:8453".to_string(),
            "sk-test".to_string(),
        )
    }

    #[test]
    fn intent_amount_usd_parses_numeric_prefix() {
        let intent = make_pay_intent();
        assert!((intent_amount_usd(&intent) - 10.5).abs() < 1e-9);
    }

    #[test]
    fn intent_amount_usd_zero_for_non_pay() {
        let intent = Intent::new(
            IntentKind::SignMessage { message: "hi".to_string(), encoding: MessageEncoding::Utf8 },
            "eip155:1".to_string(),
            "sk-test".to_string(),
        );
        assert_eq!(intent_amount_usd(&intent), 0.0);
    }

    #[test]
    fn build_call_data_pay_native_uses_recipient() {
        // M5/H12 regression: native Pay (token == None) must target the
        // recipient, not the placeholder "0x0000...0000".
        let intent = make_pay_intent();
        let cd = build_call_data(&intent.kind, &intent.chain_id).expect("build_call_data");
        assert_eq!(cd.to, "0xabcdef1234567890");
        // Native transfer carries the amount as value.
        assert_eq!(cd.value.as_deref(), Some("10.5 USDC"));
    }

    #[test]
    fn build_call_data_pay_erc20_targets_token_contract() {
        // M5: ERC-20 Pay (token == Some) targets the token contract address,
        // carries value "0x0", and encodes a `transfer(address,uint256)`
        // calldata (selector 0xa9059cbb) for the recipient.
        const RECIPIENT: &str = "0xabcdef1234567890abcdef1234567890abcdef12";
        let intent = Intent::new(
            IntentKind::Pay {
                amount: "10500000".to_string(), // 10.5 USDC in 6-decimal base units
                recipient: RECIPIENT.to_string(),
                token: Some("0x833589fcd6edb6e08f4c7c32d4f71b54cda0ed66".to_string()),
            },
            "eip155:8453".to_string(),
            "sk-test".to_string(),
        );
        let cd = build_call_data(&intent.kind, &intent.chain_id).expect("build_call_data");
        assert_eq!(cd.to, "0x833589fcd6edb6e08f4c7c32d4f71b54cda0ed66");
        assert_eq!(cd.value.as_deref(), Some("0x0"));
        let data = cd.data.expect("ERC-20 transfer must carry calldata");
        assert_eq!(&data[0..4], &[0xa9, 0x05, 0x9c, 0xbb], "transfer(address,uint256) selector");
        // Recipient is ABI-encoded in bytes 4..36 (12 zero pad + 20-byte addr).
        assert_eq!(&data[16..36], &hex::decode(RECIPIENT.trim_start_matches("0x")).expect("hex"));
    }

    #[test]
    fn build_call_data_sign_tx_uses_full_zero_address() {
        // H12: SignTransaction no longer uses the "0x0000...0000" placeholder.
        let intent = Intent::new(
            IntentKind::SignTransaction {
                tx_hex: "0xdeadbeef".to_string(),
                chain_id: "eip155:1".to_string(),
            },
            "eip155:1".to_string(),
            "sk-test".to_string(),
        );
        let cd = build_call_data(&intent.kind, &intent.chain_id).expect("build_call_data");
        assert_eq!(cd.to, "0x0000000000000000000000000000000000000000");
        assert!(!cd.to.contains(".."), "placeholder must not leak: {}", cd.to);
    }

    #[test]
    fn build_call_data_sign_message_uses_full_zero_address() {
        let intent = Intent::new(
            IntentKind::SignMessage { message: "hi".to_string(), encoding: MessageEncoding::Utf8 },
            "eip155:1".to_string(),
            "sk-test".to_string(),
        );
        let cd = build_call_data(&intent.kind, &intent.chain_id).expect("build_call_data");
        assert_eq!(cd.to, "0x0000000000000000000000000000000000000000");
    }

    #[test]
    fn build_call_data_cross_chain_targets_recipient() {
        // M5: CrossChainTransfer targets the recipient (TODO: bridge logic).
        let intent = Intent::new(
            IntentKind::CrossChainTransfer {
                amount: "100 USDC".to_string(),
                asset: "eip155:8453/erc20:0x1".to_string(),
                from_chain: "eip155:8453".to_string(),
                to_chain: "eip155:42161".to_string(),
                recipient: "0xfeedfeed".to_string(),
            },
            "eip155:8453".to_string(),
            "sk-test".to_string(),
        );
        let cd = build_call_data(&intent.kind, &intent.chain_id).expect("build_call_data");
        assert_eq!(cd.to, "0xfeedfeed");
        assert_ne!(cd.to, "0x0000000000000000000000000000000000000000");
    }

    #[test]
    fn build_call_data_sign_tx_decodes_hex() {
        let intent = Intent::new(
            IntentKind::SignTransaction {
                tx_hex: "0xdeadbeef".to_string(),
                chain_id: "eip155:1".to_string(),
            },
            "eip155:1".to_string(),
            "sk-test".to_string(),
        );
        let cd = build_call_data(&intent.kind, &intent.chain_id).expect("build_call_data");
        assert_eq!(cd.data, Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn build_call_data_sign_tx_rejects_bad_hex() {
        let intent = Intent::new(
            IntentKind::SignTransaction {
                tx_hex: "0xZZ".to_string(),
                chain_id: "eip155:1".to_string(),
            },
            "eip155:1".to_string(),
            "sk-test".to_string(),
        );
        assert!(build_call_data(&intent.kind, &intent.chain_id).is_err());
    }

    #[tokio::test]
    async fn simulate_intent_pay_returns_summary() {
        let intent = make_pay_intent();
        let rpc = MockRpcClient::new("eip155:8453");
        let summary = simulate_intent(&intent, &rpc).await.expect("simulate");
        assert_eq!(summary.intent_id, intent.id);
        assert!(summary.human_readable.contains("10.5 USDC"));
        assert!(summary.gas_estimate_usd > 0.0);
        // Mock gas: 21000 * 1e9 wei = 0.000021 ETH * 2500 USD ≈ 0.0525
        assert!(summary.gas_estimate_usd < 1.0);
    }

    #[tokio::test]
    async fn simulate_intent_pay_adds_null_warning() {
        let intent = make_pay_intent();
        let rpc = MockRpcClient::new("eip155:8453");
        let summary = simulate_intent(&intent, &rpc).await.expect("simulate");
        assert!(
            summary.warnings.iter().any(|w| w.contains("null")),
            "expected null-contract warning for Pay intent, got: {:?}",
            summary.warnings
        );
    }

    #[tokio::test]
    async fn simulate_intent_sign_message_no_null_warning() {
        let intent = Intent::new(
            IntentKind::SignMessage {
                message: "hello".to_string(),
                encoding: MessageEncoding::Utf8,
            },
            "eip155:1".to_string(),
            "sk-test".to_string(),
        );
        let rpc = MockRpcClient::new("eip155:1");
        let summary = simulate_intent(&intent, &rpc).await.expect("simulate");
        assert!(
            !summary.warnings.iter().any(|w| w.contains("null")),
            "SignMessage should not produce null-contract warning"
        );
    }

    #[tokio::test]
    async fn simulate_intent_cross_chain_includes_chains() {
        let intent = Intent::new(
            IntentKind::CrossChainTransfer {
                amount: "100 USDC".to_string(),
                asset: "eip155:8453/erc20:0x1".to_string(),
                from_chain: "eip155:8453".to_string(),
                to_chain: "eip155:42161".to_string(),
                recipient: "0xrecipient".to_string(),
            },
            "eip155:8453".to_string(),
            "sk-test".to_string(),
        );
        let rpc = MockRpcClient::new("eip155:8453");
        let summary = simulate_intent(&intent, &rpc).await.expect("simulate");
        assert!(summary.human_readable.contains("eip155:8453"));
        assert!(summary.human_readable.contains("eip155:42161"));
    }
}
