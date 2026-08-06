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
use sha3::{Digest, Keccak256};
pub use simulate::simulate_intent;

/// The canonical 20-byte zero EVM address (`address(0)`).
const ZERO_ADDRESS_EVM: &str = "0x0000000000000000000000000000000000000000";

/// Build a [`CallData`] from an [`IntentKind`].
///
/// Shared by both `simulate` and `execute` to avoid code duplication.
///
/// For `Pay` intents carrying a token, `chain` is the caller's
/// `rpc.chain_id()`; it is validated against the token's CAIP-19 chain
/// specifier so that a token from one chain is never broadcast on another.
pub(crate) fn build_call_data(kind: &IntentKind, chain: &str) -> Result<CallData, IntentError> {
    match kind {
        IntentKind::Pay { recipient, token, amount, .. } => match token {
            // Native payment: forward the raw wei hex string as the value.
            None => Ok(CallData {
                from: None,
                to: recipient.clone(),
                value: Some(amount.clone()),
                data: None,
            }),
            // ERC-20 payment: encode `transfer(address,uint256)` calldata.
            Some(token) => {
                let amount_value = parse_amount(amount)?;
                let (token_chain, token_addr) = parse_token_address(token)?;
                if let Some(tc) = &token_chain {
                    if tc != chain {
                        return Err(IntentError::InvalidChain(format!(
                            "token chain '{tc}' does not match expected chain '{chain}'"
                        )));
                    }
                }

                let recipient_bytes = parse_address(recipient)?;

                let mut data = Vec::with_capacity(4 + 32 + 32);
                data.extend_from_slice(&erc20_transfer_selector());
                data.extend_from_slice(&abi_encode_address(&recipient_bytes));
                data.extend_from_slice(&abi_encode_uint256(amount_value));

                Ok(CallData {
                    from: None,
                    to: format!("0x{}", hex::encode(&token_addr)),
                    value: Some("0x0".to_string()),
                    data: Some(data),
                })
            }
        },
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

/// Parse an amount string into a minimal-unit (wei) quantity.
///
/// Accepts a `0x`-prefixed hex string or a plain decimal integer string.
/// Anything else (e.g. `"10.5 USDC"`, empty, whitespace) is rejected.
///
/// # Note
///
/// Token decimals are not resolved here. Callers must supply the amount
/// already expressed in the token's minimal unit. A future chain lookup could
/// convert a human-readable quantity (with decimals) into the token's base
/// unit, but that is out of scope for the current intent layer.
fn parse_amount(amount: &str) -> Result<u128, IntentError> {
    let trimmed = amount.trim();
    if trimmed.is_empty() {
        return Err(IntentError::InvalidInput("amount is empty".to_string()));
    }
    if let Some(hex_str) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        u128::from_str_radix(hex_str, 16)
            .map_err(|e| IntentError::InvalidInput(format!("invalid hex amount '{amount}': {e}")))
    } else if trimmed.chars().all(|c| c.is_ascii_digit()) {
        trimmed
            .parse::<u128>()
            .map_err(|e| IntentError::InvalidInput(format!("invalid amount '{amount}': {e}")))
    } else {
        Err(IntentError::InvalidInput(format!(
            "amount '{amount}' is not a plain integer (0x-hex or decimal); \
             token decimals are resolved by the caller"
        )))
    }
}

/// Parse a CAIP-19 asset id (e.g. `eip155:8453/erc20:0x8335...`) or a bare
/// `0x...` address into an optional chain specifier and the 20-byte token
/// address.
fn parse_token_address(token: &str) -> Result<(Option<String>, Vec<u8>), IntentError> {
    let (chain, addr_str) = match token.split_once('/') {
        Some((chain_part, addr_part)) => {
            let addr_part = addr_part.strip_prefix("erc20:").ok_or_else(|| {
                IntentError::InvalidInput(format!("token '{token}' is not an erc20 asset id"))
            })?;
            (Some(chain_part.to_string()), addr_part)
        }
        None => (None, token),
    };
    let addr = parse_address(addr_str)?;
    Ok((chain, addr))
}

/// Parse a `0x`-prefixed 20-byte EVM address.
fn parse_address(addr: &str) -> Result<Vec<u8>, IntentError> {
    let bytes = hex::decode(addr.trim_start_matches("0x"))
        .map_err(|e| IntentError::InvalidInput(format!("invalid address '{addr}': {e}")))?;
    if bytes.len() != 20 {
        return Err(IntentError::InvalidInput(format!(
            "address '{addr}' is {} bytes; expected 20",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// The ERC-20 `transfer(address,uint256)` function selector
/// (`keccak256("transfer(address,uint256)")[..4]` == `0xa9059cbb`).
fn erc20_transfer_selector() -> [u8; 4] {
    let digest = Keccak256::digest(b"transfer(address,uint256)");
    [digest[0], digest[1], digest[2], digest[3]]
}

/// ABI-encode an EVM `address` into a 32-byte word (left-padded with zeroes).
fn abi_encode_address(addr: &[u8]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(addr);
    word
}

/// ABI-encode a `uint256` into a 32-byte word (right-aligned big-endian).
fn abi_encode_uint256(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECIPIENT: &str = "0x1111111111111111111111111111111111111111";
    const TOKEN: &str = "eip155:1/erc20:0x2222222222222222222222222222222222222222";
    const TOKEN_ADDR: &str = "0x2222222222222222222222222222222222222222";

    fn pay_intent(amount: &str, recipient: &str, token: Option<&str>) -> IntentKind {
        IntentKind::Pay {
            amount: amount.to_string(),
            recipient: recipient.to_string(),
            token: token.map(String::from),
        }
    }

    #[test]
    fn erc20_transfer_selector_matches_known_constant() {
        let sel = erc20_transfer_selector();
        assert_eq!(sel, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn pay_with_token_builds_transfer_calldata() {
        let kind = pay_intent("1000000", RECIPIENT, Some(TOKEN));
        let call = build_call_data(&kind, "eip155:1").expect("build");
        assert_eq!(call.to, TOKEN_ADDR);
        assert_eq!(call.value.as_deref(), Some("0x0"));
        let data = call.data.expect("token transfer must have calldata");

        // selector(4) || addr(32) || amount(32)
        assert_eq!(data.len(), 68);
        assert_eq!(&data[0..4], &erc20_transfer_selector());
        // recipient padded: 12 zero bytes then the address
        assert_eq!(&data[4..16], &[0u8; 12]);
        assert_eq!(&data[16..36], &hex::decode(RECIPIENT.trim_start_matches("0x")).unwrap());
        // amount = 1_000_000
        let mut expected_amount = [0u8; 32];
        expected_amount[16..].copy_from_slice(&1_000_000u128.to_be_bytes());
        assert_eq!(&data[36..68], &expected_amount);
    }

    #[test]
    fn pay_with_token_rejects_chain_mismatch() {
        let kind = pay_intent("1000000", RECIPIENT, Some(TOKEN));
        let err = build_call_data(&kind, "eip155:8453").expect_err("must reject mismatch");
        assert!(matches!(err, IntentError::InvalidChain(_)), "got {err}");
        assert!(err.to_string().contains("eip155:8453"));
    }

    #[test]
    fn pay_with_token_rejects_invalid_amount() {
        let kind = pay_intent("10.5 USDC", RECIPIENT, Some(TOKEN));
        let err = build_call_data(&kind, "eip155:1").expect_err("must reject non-integer");
        assert!(matches!(err, IntentError::InvalidInput(_)), "got {err}");
    }

    #[test]
    fn pay_with_token_accepts_bare_address() {
        let kind = pay_intent("1000000", RECIPIENT, Some(TOKEN_ADDR));
        let call = build_call_data(&kind, "eip155:1").expect("bare address is valid");
        assert_eq!(call.to, TOKEN_ADDR);
    }

    #[test]
    fn pay_without_token_keeps_native_semantics() {
        let kind = pay_intent("0x0de0b6b3a7640000", RECIPIENT, None);
        let call = build_call_data(&kind, "eip155:1").expect("build");
        assert_eq!(call.to, RECIPIENT);
        assert_eq!(call.value.as_deref(), Some("0x0de0b6b3a7640000"));
        assert!(call.data.is_none());
    }

    #[test]
    fn pay_with_token_accepts_hex_amount() {
        let kind = pay_intent("0x0f4240", RECIPIENT, Some(TOKEN));
        let call = build_call_data(&kind, "eip155:1").expect("build");
        let data = call.data.expect("calldata");
        let mut expected_amount = [0u8; 32];
        expected_amount[16..].copy_from_slice(&1_000_000u128.to_be_bytes());
        assert_eq!(&data[36..68], &expected_amount);
    }

    #[test]
    fn pay_with_token_accepts_zero_amount() {
        let kind = pay_intent("0", RECIPIENT, Some(TOKEN));
        let call = build_call_data(&kind, "eip155:1").expect("zero transfer is valid");
        let data = call.data.expect("calldata");
        assert_eq!(&data[36..68], &[0u8; 32]);
    }

    #[test]
    fn pay_with_token_rejects_negative_amount() {
        let kind = pay_intent("-5", RECIPIENT, Some(TOKEN));
        assert!(build_call_data(&kind, "eip155:1").is_err());
    }

    #[test]
    fn pay_with_token_rejects_bad_erc20_namespace() {
        let kind = pay_intent(
            "5",
            RECIPIENT,
            Some("eip155:1/nft:0x2222222222222222222222222222222222222222"),
        );
        let err = build_call_data(&kind, "eip155:1").expect_err("must reject non-erc20");
        assert!(err.to_string().contains("not an erc20"));
    }

    #[test]
    fn pay_with_token_rejects_non_20_byte_address() {
        let kind = pay_intent("5", RECIPIENT, Some("0x1234"));
        let err = build_call_data(&kind, "eip155:1").expect_err("must reject short address");
        assert!(matches!(err, IntentError::InvalidInput(_)), "got {err}");
    }

    #[test]
    fn parse_amount_rejects_whitespace_and_empty() {
        assert!(parse_amount("").is_err());
        assert!(parse_amount("   ").is_err());
    }

    #[test]
    fn abi_encode_address_left_pads() {
        let addr = hex::decode("1111111111111111111111111111111111111111").unwrap();
        let word = abi_encode_address(&addr);
        assert_eq!(&word[0..12], &[0u8; 12]);
        assert_eq!(&word[12..], &addr[..]);
    }
}
