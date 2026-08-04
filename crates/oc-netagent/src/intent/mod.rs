//! OneCipher Intent Layer — AI Agent Native declarative payment/signing.
//!
//! This module implements the Intent-based execution model described in
//! `docs/design.md` §6.1. AI Agents submit declarative intents (e.g.
//! "pay 10.5 USDC to 0xABC on Base"), which are:
//!
//! 1. **Simulated** — pre-flight `eth_call` + `eth_estimateGas` to show the user a human-readable
//!    summary before signing.
//! 2. **Confirmed** — user/Passkey confirms the summary.
//! 3. **Executed** — the intent is signed and broadcast (optionally via Paymaster for gasless
//!    transactions).
//!
//! Previously a standalone crate (`oc-intent`), merged into `oc-netagent` as
//! part of a workspace de-wheeling pass. `oc-netagent` is the sole consumer of
//! these types (via `HpxRpcClient`), and `oc-policy` / `oc-keyagent` must
//! remain independent.

#![deny(unsafe_code)]

pub mod error;
pub mod execute;
pub mod rpc;
pub mod schema;
pub mod simulate;

pub use error::IntentError;
pub use execute::execute_intent;
pub use rpc::{CallData, MockRpcClient, RpcClient, RpcError};
pub use schema::{Intent, IntentKind, IntentResult, IntentStatus, IntentSummary, MessageEncoding};
pub use simulate::simulate_intent;

/// The canonical 20-byte zero EVM address (`address(0)`).
const ZERO_ADDRESS_EVM: &str = "0x0000000000000000000000000000000000000000";

/// Build a [`CallData`] from an [`IntentKind`].
///
/// Shared by both `simulate` and `execute` to avoid code duplication.
/// The `chain` parameter is reserved for future use (e.g. chain-specific
/// calldata encoding); it is currently unused.
pub(crate) fn build_call_data(kind: &IntentKind, _chain: &str) -> Result<CallData, IntentError> {
    match kind {
        IntentKind::Pay { recipient, token, amount, .. } => {
            let value = token.as_ref().map_or_else(|| amount.clone(), |_| "0x0".to_string());
            Ok(CallData {
                from: None,
                to: token.clone().unwrap_or_else(|| recipient.clone()),
                value: Some(value),
                data: None,
            })
        }
        IntentKind::SignTransaction { tx_hex, .. } => Ok(CallData {
            from: None,
            to: ZERO_ADDRESS_EVM.to_string(),
            value: None,
            data: Some(
                hex::decode(tx_hex.trim_start_matches("0x"))
                    .map_err(|e| IntentError::InvalidInput(format!("invalid hex: {e}")))?,
            ),
        }),
        IntentKind::SignMessage { .. } => {
            Ok(CallData { from: None, to: ZERO_ADDRESS_EVM.to_string(), value: None, data: None })
        }
        IntentKind::CrossChainTransfer { recipient, .. } => Ok(CallData {
            from: None,
            to: recipient.clone(),
            value: Some("0x0".to_string()),
            data: None,
        }),
    }
}
