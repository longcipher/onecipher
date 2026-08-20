//! Intent CLI (Stage 2.5). Exposes the [`oc_netagent::intent`] lifecycle to AI Agents:
//!
//! - `onecipher intent submit --json '...' --chain eip155:8453 --session-key sk-1` Simulates the
//!   intent, prints a human-readable summary, prompts for confirmation (unless `--yes`), then
//!   executes it.
//! - `onecipher intent simulate --json '...' --chain eip155:8453 --session-key sk-1` Dry-run:
//!   prints the [`IntentSummary`] as JSON without executing.
//! - `onecipher intent execute --json '...' --chain eip155:8453 --session-key sk-1` Executes an
//!   already-confirmed intent (skips the simulation + prompt).
//!
//! When `--rpc-url` is provided, the CLI uses [`oc_netagent::HpxRpcClient`] (a
//! real EVM JSON-RPC client backed by `hpx`) for simulation/execution. When
//! `--rpc-url` is absent, it falls back to [`MockRpcClient`] for local testing.

use std::io::{self, BufRead, IsTerminal, Write};

use oc_netagent::intent::{
    Intent, IntentError, IntentKind, IntentResult, IntentStatus, IntentSummary, MessageEncoding,
    MockRpcClient, RpcClient, execute_intent, simulate_intent,
};
use serde_json::Value;

use crate::CliError;

// ---------------------------------------------------------------------------
// Intent JSON parsing
// ---------------------------------------------------------------------------

/// Parse the `--json` CLI argument into an [`IntentKind`].
///
/// The JSON must be an object with a `"type"` field set to one of:
/// `Pay`, `SignTransaction`, `SignMessage`, `CrossChainTransfer`.
fn parse_intent_kind(json_str: &str) -> Result<IntentKind, CliError> {
    let value: Value = serde_json::from_str(json_str)
        .map_err(|e| CliError::InvalidArgs(format!("invalid intent JSON: {e}")))?;

    let kind = match value.get("type").and_then(Value::as_str) {
        Some(t) => t,
        None => {
            return Err(CliError::InvalidArgs(
                "intent JSON must have a \"type\" field (Pay|SignTransaction|SignMessage|CrossChainTransfer)".into(),
            ));
        }
    };

    match kind {
        "Pay" => {
            let amount = value
                .get("amount")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::InvalidArgs("Pay intent requires \"amount\" string".into())
                })?
                .to_string();
            let recipient = value
                .get("recipient")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::InvalidArgs("Pay intent requires \"recipient\" string".into())
                })?
                .to_string();
            let token = value.get("token").and_then(Value::as_str).map(String::from);
            Ok(IntentKind::Pay { amount, recipient, token })
        }
        "SignTransaction" => {
            let tx_hex = value
                .get("tx_hex")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::InvalidArgs(
                        "SignTransaction intent requires \"tx_hex\" string".into(),
                    )
                })?
                .to_string();
            let chain_id = value
                .get("chain_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::InvalidArgs(
                        "SignTransaction intent requires \"chain_id\" string".into(),
                    )
                })?
                .to_string();
            Ok(IntentKind::SignTransaction { tx_hex, chain_id })
        }
        "SignMessage" => {
            let message = value
                .get("message")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::InvalidArgs("SignMessage intent requires \"message\" string".into())
                })?
                .to_string();
            let encoding_str = value.get("encoding").and_then(Value::as_str).unwrap_or("utf8");
            let encoding = match encoding_str {
                "utf8" => MessageEncoding::Utf8,
                "hex" => MessageEncoding::Hex,
                other => {
                    return Err(CliError::InvalidArgs(format!(
                        "invalid encoding '{other}' (expected utf8|hex)"
                    )));
                }
            };
            Ok(IntentKind::SignMessage { message, encoding })
        }
        "CrossChainTransfer" => {
            let amount = value
                .get("amount")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::InvalidArgs(
                        "CrossChainTransfer intent requires \"amount\" string".into(),
                    )
                })?
                .to_string();
            let asset = value
                .get("asset")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::InvalidArgs(
                        "CrossChainTransfer intent requires \"asset\" string".into(),
                    )
                })?
                .to_string();
            let from_chain = value
                .get("from_chain")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::InvalidArgs(
                        "CrossChainTransfer intent requires \"from_chain\" string".into(),
                    )
                })?
                .to_string();
            let to_chain = value
                .get("to_chain")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::InvalidArgs(
                        "CrossChainTransfer intent requires \"to_chain\" string".into(),
                    )
                })?
                .to_string();
            let recipient = value
                .get("recipient")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::InvalidArgs(
                        "CrossChainTransfer intent requires \"recipient\" string".into(),
                    )
                })?
                .to_string();
            Ok(IntentKind::CrossChainTransfer { amount, asset, from_chain, to_chain, recipient })
        }
        other => Err(CliError::InvalidArgs(format!(
            "unknown intent type: '{other}' (expected Pay|SignTransaction|SignMessage|CrossChainTransfer)"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Confirmation prompt
// ---------------------------------------------------------------------------

/// Returns `true` if stdin is an interactive terminal AND no explicit
/// non-interactive override is set via the `OC_NONINTERACTIVE` env var.
///
/// Under `#[cfg(test)]`, stdin is ALWAYS treated as non-interactive so unit
/// tests do not block on `read_line()` waiting for TTY input.
fn is_interactive_stdin() -> bool {
    if cfg!(test) {
        return false;
    }
    if std::env::var("OC_NONINTERACTIVE").is_ok() {
        return false;
    }
    io::stdin().is_terminal()
}

/// Prompt the user with a y/N confirmation. Returns `true` if they answer `y`.
///
/// Non-interactive stdin (pipe, `OC_NONINTERACTIVE` env) defaults to `false`
/// to prevent accidental execution in scripts — the caller must pass `--yes`
/// to skip the prompt.
fn prompt_yes_no(prompt: &str) -> bool {
    if !is_interactive_stdin() {
        // Non-interactive: refuse by default.
        eprintln!("{prompt} [y/N] (non-interactive; pass --yes to confirm)");
        return false;
    }
    eprint!("{prompt} [y/N] ");
    io::stderr().flush().ok();
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

// ---------------------------------------------------------------------------
// RPC client selection
// ---------------------------------------------------------------------------

/// Build an RPC client for the given chain.
///
/// When `rpc_url` is provided, returns a real [`oc_netagent::HpxRpcClient`]
/// backed by `hpx` (EVM JSON-RPC). When `rpc_url` is `None`, or when the real
/// client cannot be constructed, falls back to [`MockRpcClient`] so that local
/// testing without a running node continues to work.
fn build_rpc_client(chain_id: &str, rpc_url: Option<&str>) -> Box<dyn RpcClient> {
    if let Some(url) = rpc_url {
        match oc_netagent::HpxRpcClient::new(chain_id, url) {
            Ok(c) => return Box::new(c),
            Err(e) => eprintln!("[WARN] failed to create RPC client: {e}; falling back to mock"),
        }
    }
    Box::new(MockRpcClient::new(chain_id))
}

// ---------------------------------------------------------------------------
// Subcommand entry points
// ---------------------------------------------------------------------------

/// Entry point for `onecipher intent submit`.
///
/// Full lifecycle: parse → simulate → display summary → confirm → execute.
pub(crate) fn run_submit(
    json: &str,
    chain_id: &str,
    session_key_id: &str,
    yes: bool,
    rpc_url: Option<&str>,
) -> Result<(), CliError> {
    let kind = parse_intent_kind(json)?;
    let intent = Intent::new(kind, chain_id.to_string(), session_key_id.to_string());
    let rpc = build_rpc_client(chain_id, rpc_url);

    crate::shared_runtime().block_on(async move {
        // 1. Simulate
        let summary = run_simulation(&intent, &*rpc).await?;

        // 2. Prompt for confirmation (unless --yes)
        if !yes {
            let confirmed = prompt_yes_no(&format!(
                "{}\n  gas: ${:.4}, total: ${:.2}\n  warnings: {}\nConfirm?",
                summary.human_readable,
                summary.gas_estimate_usd,
                summary.total_cost_usd,
                if summary.warnings.is_empty() {
                    "none".to_string()
                } else {
                    summary.warnings.join("; ")
                }
            ));
            if !confirmed {
                // M14: user rejected the intent at the confirmation prompt.
                // Surface a Denied IntentResult (printed as JSON for
                // programmatic consumers) instead of silently returning Ok(()).
                // `Approved` was removed from IntentStatus — `Denied` is the new
                // explicit rejection state. `run_submit` returns
                // `Result<(), CliError>`, so the structured denial is emitted
                // via `print_result` (matching the success path) and we return
                // `Ok(())`.
                eprintln!("intent cancelled by user");
                let denied = IntentResult {
                    intent_id: intent.id,
                    status: IntentStatus::Denied,
                    tx_hash: None,
                    receipt: None,
                    error: Some("cancelled by user".to_string()),
                };
                print_result(&denied);
                return Ok(());
            }
        }

        // 3. Execute
        let result = run_execution(&intent, &*rpc).await?;

        // 4. Print result
        print_result(&result);
        Ok(())
    })
}

/// Entry point for `onecipher intent simulate`.
///
/// Dry-run: parses, simulates, prints the summary as JSON. Does not execute.
pub(crate) fn run_simulate(
    json: &str,
    chain_id: &str,
    session_key_id: &str,
    rpc_url: Option<&str>,
) -> Result<(), CliError> {
    let kind = parse_intent_kind(json)?;
    let intent = Intent::new(kind, chain_id.to_string(), session_key_id.to_string());
    let rpc = build_rpc_client(chain_id, rpc_url);

    crate::shared_runtime().block_on(async move {
        let summary = run_simulation(&intent, &*rpc).await?;
        print_summary(&summary);
        Ok(())
    })
}

/// Entry point for `onecipher intent execute`.
///
/// Skips simulation + prompt; executes the intent directly. Intended for
/// programmatic flows where confirmation is handled out-of-band.
pub(crate) fn run_execute(
    json: &str,
    chain_id: &str,
    session_key_id: &str,
    rpc_url: Option<&str>,
) -> Result<(), CliError> {
    let kind = parse_intent_kind(json)?;
    let intent = Intent::new(kind, chain_id.to_string(), session_key_id.to_string());
    let rpc = build_rpc_client(chain_id, rpc_url);

    crate::shared_runtime().block_on(async move {
        let result = run_execution(&intent, &*rpc).await?;
        print_result(&result);
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Internal helpers (async)
// ---------------------------------------------------------------------------

async fn run_simulation(intent: &Intent, rpc: &dyn RpcClient) -> Result<IntentSummary, CliError> {
    simulate_intent(intent, rpc).await.map_err(map_intent_error)
}

async fn run_execution(intent: &Intent, rpc: &dyn RpcClient) -> Result<IntentResult, CliError> {
    // TODO: wire the signer to the Key-Agent over UDS (see oc-netagent /
    // oc-keyagent). For now we return the unsigned tx bytes unchanged so the
    // build stays green and the MockRpcClient (which does not validate
    // signatures) can exercise the full execute → broadcast → receipt path.
    // Real signing is deferred to integration with the Key-Agent UDS channel.
    let signer =
        |_key: &oc_netagent::intent::SigningKeyRef,
         tx_bytes: &[u8]|
         -> Result<Vec<u8>, oc_netagent::intent::IntentError> { Ok(tx_bytes.to_vec()) };
    execute_intent(intent, rpc, signer).await.map_err(map_intent_error)
}

fn map_intent_error(e: IntentError) -> CliError {
    CliError::InvalidArgs(format!("intent error: {e}"))
}

fn print_summary(summary: &IntentSummary) {
    let json =
        serde_json::to_string_pretty(summary).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
    println!("{json}");
}

fn print_result(result: &IntentResult) {
    let json =
        serde_json::to_string_pretty(result).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
    println!("{json}");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_intent_kind
    // -----------------------------------------------------------------------

    #[test]
    fn parse_intent_kind_pay_minimal() {
        let json = r#"{"type":"Pay","amount":"10.5 USDC","recipient":"0xabc"}"#;
        let kind = parse_intent_kind(json).expect("parse");
        match kind {
            IntentKind::Pay { amount, recipient, token } => {
                assert_eq!(amount, "10.5 USDC");
                assert_eq!(recipient, "0xabc");
                assert!(token.is_none());
            }
            other => panic!("expected Pay, got {other:?}"),
        }
    }

    #[test]
    fn parse_intent_kind_pay_with_token() {
        let json = r#"{"type":"Pay","amount":"1 USDC","recipient":"0xabc","token":"eip155:8453/erc20:0x1"}"#;
        let kind = parse_intent_kind(json).expect("parse");
        match kind {
            IntentKind::Pay { token, .. } => {
                assert_eq!(token.as_deref(), Some("eip155:8453/erc20:0x1"));
            }
            other => panic!("expected Pay, got {other:?}"),
        }
    }

    #[test]
    fn parse_intent_kind_sign_transaction() {
        let json = r#"{"type":"SignTransaction","tx_hex":"0xdead","chain_id":"eip155:1"}"#;
        let kind = parse_intent_kind(json).expect("parse");
        match kind {
            IntentKind::SignTransaction { tx_hex, chain_id } => {
                assert_eq!(tx_hex, "0xdead");
                assert_eq!(chain_id, "eip155:1");
            }
            other => panic!("expected SignTransaction, got {other:?}"),
        }
    }

    #[test]
    fn parse_intent_kind_sign_message_default_utf8() {
        let json = r#"{"type":"SignMessage","message":"hello"}"#;
        let kind = parse_intent_kind(json).expect("parse");
        match kind {
            IntentKind::SignMessage { message, encoding } => {
                assert_eq!(message, "hello");
                assert_eq!(encoding, MessageEncoding::Utf8);
            }
            other => panic!("expected SignMessage, got {other:?}"),
        }
    }

    #[test]
    fn parse_intent_kind_sign_message_hex_encoding() {
        let json = r#"{"type":"SignMessage","message":"deadbeef","encoding":"hex"}"#;
        let kind = parse_intent_kind(json).expect("parse");
        match kind {
            IntentKind::SignMessage { encoding, .. } => assert_eq!(encoding, MessageEncoding::Hex),
            other => panic!("expected SignMessage, got {other:?}"),
        }
    }

    #[test]
    fn parse_intent_kind_cross_chain_transfer() {
        let json = r#"{
            "type":"CrossChainTransfer",
            "amount":"100 USDC",
            "asset":"eip155:8453/erc20:0x1",
            "from_chain":"eip155:8453",
            "to_chain":"eip155:42161",
            "recipient":"0xdef"
        }"#;
        let kind = parse_intent_kind(json).expect("parse");
        match kind {
            IntentKind::CrossChainTransfer { amount, from_chain, to_chain, .. } => {
                assert_eq!(amount, "100 USDC");
                assert_eq!(from_chain, "eip155:8453");
                assert_eq!(to_chain, "eip155:42161");
            }
            other => panic!("expected CrossChainTransfer, got {other:?}"),
        }
    }

    #[test]
    fn parse_intent_kind_rejects_missing_type() {
        let json = r#"{"amount":"10 USDC"}"#;
        assert!(matches!(parse_intent_kind(json), Err(CliError::InvalidArgs(_))));
    }

    #[test]
    fn parse_intent_kind_rejects_unknown_type() {
        let json = r#"{"type":"Foo","amount":"10"}"#;
        assert!(matches!(parse_intent_kind(json), Err(CliError::InvalidArgs(_))));
    }

    #[test]
    fn parse_intent_kind_rejects_invalid_json() {
        let json = r"not json";
        assert!(matches!(parse_intent_kind(json), Err(CliError::InvalidArgs(_))));
    }

    #[test]
    fn parse_intent_kind_rejects_pay_missing_amount() {
        let json = r#"{"type":"Pay","recipient":"0xabc"}"#;
        assert!(matches!(parse_intent_kind(json), Err(CliError::InvalidArgs(_))));
    }

    #[test]
    fn parse_intent_kind_rejects_bad_encoding() {
        let json = r#"{"type":"SignMessage","message":"hi","encoding":"binary"}"#;
        assert!(matches!(parse_intent_kind(json), Err(CliError::InvalidArgs(_))));
    }

    // -----------------------------------------------------------------------
    // build_rpc_client
    // -----------------------------------------------------------------------

    #[test]
    fn build_rpc_client_returns_mock_with_chain_id() {
        let rpc = build_rpc_client("eip155:1", None);
        assert_eq!(rpc.chain_id(), "eip155:1");
    }

    #[test]
    fn build_rpc_client_uses_hpx_client_when_rpc_url_provided() {
        // When rpc_url is provided, build_rpc_client returns a real HpxRpcClient.
        // chain_id() must echo back the configured chain without making any RPC calls.
        let rpc = build_rpc_client("eip155:8453", Some("https://eth.example.com"));
        assert_eq!(rpc.chain_id(), "eip155:8453");
    }

    // -----------------------------------------------------------------------
    // End-to-end subcommand flows (via tokio runtime)
    // -----------------------------------------------------------------------

    #[test]
    fn run_simulate_pay_intent_prints_summary() {
        let json = r#"{"type":"Pay","amount":"10.5 USDC","recipient":"0xabc"}"#;
        let result = run_simulate(json, "eip155:8453", "sk-test", None);
        assert!(result.is_ok(), "run_simulate should succeed");
    }

    #[test]
    fn run_simulate_sign_message_intent() {
        let json = r#"{"type":"SignMessage","message":"hello"}"#;
        let result = run_simulate(json, "eip155:1", "sk-test", None);
        assert!(result.is_ok());
    }

    #[test]
    fn run_simulate_rejects_bad_json() {
        let result = run_simulate("not json", "eip155:1", "sk-test", None);
        assert!(matches!(result, Err(CliError::InvalidArgs(_))));
    }

    #[test]
    fn run_execute_pay_intent_succeeds_with_mock_rpc() {
        // Native Pay amount must be a hex wei string (1 * 10^18 wei = 1 token).
        // `build_unsigned_eip1559_tx` rejects human-readable amounts (e.g.
        // "1 USDC") rather than silently encoding 0 wei.
        let json = r#"{"type":"Pay","amount":"0x0de0b6b3a7640000","recipient":"0xabcabcabcabcabcabcabcabcabcabcabca"}"#;
        let result = run_execute(json, "eip155:8453", "sk-test", None);
        assert!(result.is_ok(), "run_execute should succeed with mock RPC");
    }

    #[test]
    fn run_execute_sign_transaction_intent() {
        let json = r#"{"type":"SignTransaction","tx_hex":"0xdeadbeef","chain_id":"eip155:1"}"#;
        let result = run_execute(json, "eip155:1", "sk-test", None);
        assert!(result.is_ok());
    }

    #[test]
    fn run_submit_with_yes_flag_skips_prompt() {
        // --yes skips the interactive prompt, so this should succeed even
        // in non-interactive test contexts. Native Pay amount is hex wei.
        let json = r#"{"type":"Pay","amount":"0x0de0b6b3a7640000","recipient":"0xabcabcabcabcabcabcabcabcabcabcabca"}"#;
        let result = run_submit(json, "eip155:8453", "sk-test", true, None);
        assert!(result.is_ok(), "run_submit --yes should succeed");
    }

    #[test]
    fn run_submit_without_yes_in_noninteractive_cancels_gracefully() {
        // In test context stdin is not a terminal, so prompt returns false.
        // The function should return Ok(()) with "cancelled" message.
        let json = r#"{"type":"Pay","amount":"1 USDC","recipient":"0xabc"}"#;
        let result = run_submit(json, "eip155:8453", "sk-test", false, None);
        assert!(result.is_ok(), "cancelled submit should return Ok(())");
    }

    #[test]
    fn run_submit_cross_chain_transfer_with_yes() {
        let json = r#"{
            "type":"CrossChainTransfer",
            "amount":"100 USDC",
            "asset":"eip155:8453/erc20:0x1",
            "from_chain":"eip155:8453",
            "to_chain":"eip155:42161",
            "recipient":"0xdefdefdefdefdefdefdefdefdefdefdefdef"
        }"#;
        let result = run_submit(json, "eip155:8453", "sk-test", true, None);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // prompt_yes_no behavior in non-interactive context
    // -----------------------------------------------------------------------

    #[test]
    fn prompt_yes_no_returns_false_in_noninteractive_context() {
        // In test context, stdin is not a terminal.
        assert!(!prompt_yes_no("Confirm?"));
    }

    // -----------------------------------------------------------------------
    // print helpers (smoke — just verify no panic)
    // -----------------------------------------------------------------------

    #[test]
    fn print_summary_does_not_panic() {
        let summary = IntentSummary {
            intent_id: uuid::Uuid::new_v4(),
            human_readable: "test".to_string(),
            gas_estimate_usd: 0.01,
            total_cost_usd: 10.51,
            warnings: vec![],
            simulation_tx_hash: None,
        };
        print_summary(&summary);
    }

    #[test]
    fn print_result_does_not_panic() {
        let result = IntentResult {
            intent_id: uuid::Uuid::new_v4(),
            status: oc_netagent::intent::IntentStatus::Confirmed,
            tx_hash: Some("0xabc".to_string()),
            receipt: Some(serde_json::json!({"status": "0x1"})),
            error: None,
        };
        print_result(&result);
    }
}
