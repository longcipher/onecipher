use tracing::debug;

use super::{
    amount_numeric_prefix, build_call_data,
    error::IntentError,
    rpc::RpcClient,
    schema::{Intent, IntentKind, IntentSummary},
};

/// Simulate an intent before execution.
///
/// USD figures are best-effort: when the native token price feed is
/// unavailable (H-05) the simulation still completes and reports unknown
/// (`None`) costs plus an explicit warning instead of failing outright.
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
    // H-05: price-feed unavailability degrades the USD figures to "unknown"
    // rather than aborting the whole simulation.
    let native_price = match rpc.native_price_usd().await {
        Ok(price) => Some(price),
        Err(e) => {
            debug!(error = %e, "native price feed unavailable; USD estimates omitted");
            None
        }
    };

    let gas_cost_wei = u128::from(gas_estimate) * u128::from(gas_price);
    let gas_cost_usd = native_price.map(|price| (gas_cost_wei as f64 / 1e18) * price);

    // 5. Get intent amount in USD (`None` = no human-readable magnitude)
    let amount_usd = intent_amount_usd(intent);

    // 6. Generate warnings
    let mut warnings = Vec::new();
    if sim_result.is_null() && !matches!(intent.kind, IntentKind::SignMessage { .. }) {
        warnings.push("simulation returned null — contract may not exist".to_string());
    }
    if let Some(cost) = gas_cost_usd &&
        cost > 5.0
    {
        warnings.push(format!("high gas cost: ${cost:.2}"));
    }
    if native_price.is_none() {
        warnings.push("native token price unavailable — USD cost estimates omitted".to_string());
    }

    // 7. Generate human-readable summary
    let human_readable = format_summary(intent, gas_cost_usd, amount_usd);

    // M-08: totals are only computed from KNOWN components — an unknown
    // amount or unknown gas cost renders as unknown, never as a silent zero.
    let total_cost_usd = match (gas_cost_usd, amount_usd) {
        (Some(gas), Some(amount)) => Some(gas + amount),
        _ => None,
    };

    Ok(IntentSummary {
        intent_id: intent.id,
        human_readable,
        gas_estimate_usd: gas_cost_usd,
        total_cost_usd,
        warnings,
        simulation_tx_hash: None,
    })
}

/// Best-effort USD magnitude of the intent's transferred amount.
///
/// Returns `None` when the amount has no extractable finite decimal prefix
/// (M-08) — callers must render that as "unknown", never as `$0`.
fn intent_amount_usd(intent: &Intent) -> Option<f64> {
    match &intent.kind {
        IntentKind::Pay { amount, .. } => amount_numeric_prefix(amount),
        _ => None,
    }
}

/// Truncate an address-like string for display on a char boundary (M-09).
///
/// The input may be attacker-controlled arbitrary text; byte slicing would
/// panic when the cut point lands inside a multi-byte UTF-8 character.
fn truncate_display(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max_chars).collect();
    format!("{truncated}…")
}

/// Render a USD figure, or the literal "unknown" when unavailable (M-08).
fn format_usd(value: Option<f64>) -> String {
    match value {
        Some(v) => format!("${v:.2}"),
        None => "unknown".to_string(),
    }
}

fn format_summary(intent: &Intent, gas_cost_usd: Option<f64>, amount_usd: Option<f64>) -> String {
    match &intent.kind {
        IntentKind::Pay { amount, recipient, .. } => {
            let total = match (gas_cost_usd, amount_usd) {
                (Some(gas), Some(amount)) => Some(gas + amount),
                _ => None,
            };
            format!(
                "Send {} to {} on {} (est. gas: {}, total: {})",
                amount,
                truncate_display(recipient, 10),
                intent.chain_id,
                format_usd(gas_cost_usd),
                format_usd(total)
            )
        }
        IntentKind::SignTransaction { .. } => format!(
            "Sign transaction on {} (est. gas: {})",
            intent.chain_id,
            format_usd(gas_cost_usd)
        ),
        IntentKind::SignMessage { .. } => format!("Sign message on {}", intent.chain_id),
        // M-04b: CrossChainTransfer is never simulated or executed until
        // bridge integration lands; build_call_data rejects it earlier, so
        // this arm is only reachable through direct helper calls.
        IntentKind::CrossChainTransfer { .. } => {
            "Cross-chain transfer is not supported".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            rpc::MockRpcClient,
            schema::{Intent, IntentKind, MessageEncoding},
        },
        *,
    };

    fn make_pay_intent() -> Intent {
        Intent::new(
            IntentKind::Pay {
                // On-chain amounts are hex wei quantities once they reach the
                // builder; the shared strict parser (M-08) accepts exactly
                // these.
                amount: "0x0de0b6b3a7640000".to_string(),
                recipient: "0xabcdef1234567890abcdef1234567890abcdef12".to_string(),
                token: None,
            },
            "eip155:8453".to_string(),
            "sk-test".to_string(),
        )
    }

    #[test]
    fn intent_amount_usd_parses_decimal_prefix() {
        let intent = Intent::new(
            IntentKind::Pay {
                amount: "1000000".to_string(),
                recipient: "0xabcdef1234567890abcdef1234567890abcdef12".to_string(),
                token: None,
            },
            "eip155:8453".to_string(),
            "sk-test".to_string(),
        );
        assert_eq!(intent_amount_usd(&intent), Some(1_000_000.0));
    }

    #[test]
    fn intent_amount_usd_none_for_hex_amount() {
        // M-08 regression: a hex wei amount has no decimal USD magnitude —
        // it must be reported as unknown (None), never silently as $0.
        let intent = make_pay_intent();
        assert_eq!(intent_amount_usd(&intent), None);
    }

    #[test]
    fn intent_amount_usd_none_for_non_pay() {
        let intent = Intent::new(
            IntentKind::SignMessage { message: "hi".to_string(), encoding: MessageEncoding::Utf8 },
            "eip155:1".to_string(),
            "sk-test".to_string(),
        );
        assert_eq!(intent_amount_usd(&intent), None);
    }

    #[test]
    fn truncate_display_respects_char_boundaries() {
        // M-09 regression: multi-byte characters must never panic.
        let emoji = "🦊🦊🦊🦊🦊🦊🦊🦊🦊🦊🦊🦊";
        let truncated = truncate_display(emoji, 10);
        assert!(truncated.chars().count() <= 11); // 10 chars + ellipsis
        assert_eq!(truncate_display("short", 10), "short");
    }

    #[test]
    fn build_call_data_pay_native_uses_recipient() {
        // Native Pay (token == None) must target the recipient and carry the
        // amount as a hex wei value.
        let intent = make_pay_intent();
        let cd = build_call_data(&intent.kind, &intent.chain_id).expect("build_call_data");
        assert_eq!(cd.to, "0xabcdef1234567890abcdef1234567890abcdef12");
        // Canonical EVM quantity form omits leading zeros.
        assert_eq!(cd.value.as_deref(), Some("0xde0b6b3a7640000"));
    }

    #[test]
    fn build_call_data_sign_tx_uses_full_zero_address() {
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
    fn build_call_data_cross_chain_is_unsupported() {
        // M-04b regression: CrossChainTransfer must fail closed — signing a
        // zero-value no-op transfer while the user approved an asset move is
        // a trust violation.
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
        let err = build_call_data(&intent.kind, &intent.chain_id).expect_err("must be unsupported");
        assert!(matches!(err, super::super::IntentError::Unsupported(_)), "got: {err}");
    }

    #[tokio::test]
    async fn simulate_intent_pay_returns_summary() {
        let intent = make_pay_intent();
        let rpc = MockRpcClient::new("eip155:8453");
        let summary = simulate_intent(&intent, &rpc).await.expect("simulate");
        assert_eq!(summary.intent_id, intent.id);
        assert!(summary.human_readable.contains("0x0de0b6b3"));
        // Mock gas: 21000 * 1e9 wei = 0.000021 ETH * 2500 USD ≈ 0.0525
        let gas = summary.gas_estimate_usd.expect("gas known with mock price feed");
        assert!(gas > 0.0 && gas < 1.0);
    }

    #[tokio::test]
    async fn simulate_intent_completes_when_price_unavailable() {
        // H-05 regression: a failing price feed must NOT abort simulation.
        let intent = make_pay_intent();
        let rpc = MockRpcClient::new("eip155:8453").with_failing_native_price();
        let summary = simulate_intent(&intent, &rpc).await.expect("simulate must succeed");
        assert!(summary.gas_estimate_usd.is_none(), "USD figures unknown without price");
        assert!(summary.total_cost_usd.is_none());
        assert!(
            summary.warnings.iter().any(|w| w.contains("price unavailable")),
            "expected price-unavailable warning, got: {:?}",
            summary.warnings
        );
        assert!(summary.human_readable.contains("unknown"), "summary: {}", summary.human_readable);
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
}
