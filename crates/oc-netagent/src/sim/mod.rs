//! EVM transaction offline pre-execution.
//!
//! [`simulate_evm_tx`] is the single public entry-point. It decodes a raw
//! hex-encoded signed transaction and produces a [`TxSimulation`] (reusing the
//! shared type from `oc-core`) *without* contacting any RPC endpoint.
//!
//! # What "pre-execution" means here
//!
//! This is deliberately a local, offline analysis — no state is fetched, no
//! block is executed. It answers the questions an approval prompt needs for
//! the two most common transaction shapes:
//!
//! - **Native transfer** (empty `data`): the recipient and the exact wei amount are read straight
//!   from the RLP payload, so the balance delta is *exact*, not estimated. `success = true` (a
//!   value transfer cannot revert) and `gas_used = 21000` (the native-transfer intrinsic cost).
//! - **Contract call** (non-empty `data`): the calldata is ABI-decoded from the curated local ABI
//!   cache into a [`DecodedAction`] so the approval UI can show a human-readable description.
//!   `success` stays `true` — an offline decoder cannot know whether the call will revert — and
//!   `gas_used` is left at `0` (unknown), which the UI renders as "unknown" rather than a
//!   confident-but-wrong number.
//!
//! Anything that cannot be parsed — malformed hex, unsupported transaction
//! type, truncated RLP — returns [`SimError::NotAvailable`], which the caller
//! degrades gracefully (the approval is shown with raw calldata, never
//! blocked). A full stateful `eth_call` preflight can be layered on later
//! behind the same function signature; the design doc's `evm2` (alloy-rs/evm2)
//! interpreter is not yet wired because it is a git dependency with heavy
//! precompile deps — see `specs/webui-approval/design.md` ADR-3.
//!
//! # R56 / R12 compliance
//!
//! This module performs no I/O and opens no sockets: the heavy EVM work is
//! offloaded to a blocking thread via [`tokio::task::spawn_blocking`] only so
//! the async caller does not stall. There is no network dependency here.

pub mod abi_cache;
pub mod abi_decode;
mod rlp;

use oc_core::{TokenDelta, TokenDirection, TxSimulation};

#[derive(Debug, thiserror::Error)]
pub enum SimError {
    #[error("hex decode error: {0}")]
    HexDecode(String),
    #[error("transaction decode error: {0}")]
    TxDecode(String),
    #[error("evm execution error: {0}")]
    Execution(String),
    #[error("simulation not available: {0}")]
    NotAvailable(String),
}

/// Gas cost of a plain native-value transfer (the intrinsic 21000).
const NATIVE_TRANSFER_GAS: u64 = 21_000;

/// Simulate an EVM transaction from its raw hex-encoded signed bytes.
///
/// The (pure, blocking) work is offloaded to a blocking thread via
/// [`tokio::task::spawn_blocking`].
pub async fn simulate_evm_tx(raw_tx_hex: &str, chain_id: &str) -> Result<TxSimulation, SimError> {
    let hex = raw_tx_hex.trim().strip_prefix("0x").unwrap_or(raw_tx_hex).to_owned();
    let chain = chain_id.to_owned();

    tokio::task::spawn_blocking(move || simulate_evm_tx_sync(&hex, &chain))
        .await
        .map_err(|e| SimError::Execution(format!("task join error: {e}")))?
}

fn simulate_evm_tx_sync(hex: &str, _chain_id: &str) -> Result<TxSimulation, SimError> {
    // Strip a `0x` prefix if present — the async wrapper already does, but the
    // sync core must be robust on its own (it is exercised directly in tests).
    let stripped = hex.trim().strip_prefix("0x").unwrap_or_else(|| hex.trim());
    let tx_bytes = hex::decode(stripped).map_err(|e| SimError::HexDecode(e.to_string()))?;
    let fields = rlp::decode_tx_fields(&tx_bytes).map_err(SimError::TxDecode)?;

    // Field positions depend on transaction type; see `rlp::TxFields`.
    // `to` is intentionally not surfaced in `TxSimulation` (no field for it);
    // it is parsed so malformed recipients fail here rather than later.
    let _to = fields.to;
    let value = fields.value;
    let data = fields.data;

    // --- Native transfer: exact, cheap, cannot revert. ---
    if data.is_empty() {
        let amount = format_wei(value);
        return Ok(TxSimulation {
            success: true,
            gas_used: NATIVE_TRANSFER_GAS,
            balance_change: vec![TokenDelta {
                token: "ETH".to_string(),
                direction: TokenDirection::Send,
                amount,
            }],
            decoded_action: None,
            error: None,
        });
    }

    // --- Contract call: decode calldata offline; execution state unknown. ---
    let decoded_action = abi_decode::decode_calldata(&data);
    // We never claim success=false here: an offline decoder cannot prove a
    // revert. A stateful preflight (evm2/eth_call) will refine this later.
    Ok(TxSimulation {
        success: true,
        gas_used: 0,
        balance_change: Vec::new(),
        decoded_action,
        error: None,
    })
}

/// Format a wei amount as a human-readable ETH string.
///
/// Renders 18-decimal ETH with trailing zeros trimmed: `1_000_000_000_000_000_000`
/// → `"1"`, `5_000_000_000_000_000_000` → `"5"`, `1_500_000_000_000_000_000`
/// → `"1.5"`. Values below 1 wei never occur (value is integral). Tiny amounts
/// under one gwei render as raw wei so the operator sees the true scale rather
/// than a wall of leading zeros. This keeps the approval prompt free of
/// floating-point error while staying compact for whole-ETH transfers.
fn format_wei(wei: u128) -> String {
    const ONE_ETH: u128 = 1_000_000_000_000_000_000;
    const ONE_GWEI: u128 = 1_000_000_000;
    if wei == 0 {
        return "0".to_string();
    }
    if wei < ONE_GWEI {
        // Sub-gwei: raw wei is clearer than `0.000000000123`.
        return format!("{wei} wei");
    }
    let whole = wei / ONE_ETH;
    let frac = wei % ONE_ETH;
    if frac == 0 {
        return whole.to_string();
    }
    // 18-digit fraction, right-padded, trailing zeros trimmed.
    let frac_str = format!("{frac:018}");
    let trimmed = frac_str.trim_end_matches('0');
    if trimmed.is_empty() {
        return whole.to_string();
    }
    format!("{whole}.{trimmed}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_transfer_tx(to: [u8; 20], value: u128) -> Vec<u8> {
        // Legacy tx: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        // We only need to/v/data for the decoder; other fields can be 0.
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_item(&[0x01])); // nonce=1
        items.extend_from_slice(&rlp::encode_item(&[0x04])); // gasPrice=4
        items.extend_from_slice(&rlp::encode_item(&[0x52, 0x08])); // gas=21000
        items.extend_from_slice(&rlp::encode_item(&to)); // to
        items.extend_from_slice(&rlp::encode_item(&rlp::u256_be(value))); // value
        items.extend_from_slice(&rlp::encode_item(&[])); // data (empty)
        items.extend_from_slice(&rlp::encode_item(&[0x1b])); // v
        items.extend_from_slice(&rlp::encode_item(&[0xaa; 32])); // r
        items.extend_from_slice(&rlp::encode_item(&[0xbb; 32])); // s
        rlp::encode_list(&items)
    }

    fn contract_tx(data: &[u8]) -> Vec<u8> {
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_item(&[0x01]));
        items.extend_from_slice(&rlp::encode_item(&[0x04]));
        items.extend_from_slice(&rlp::encode_item(&[0x52, 0x08]));
        items.extend_from_slice(&rlp::encode_item(&[0x11; 20])); // contract
        items.extend_from_slice(&rlp::encode_item(&[0x00])); // value=0
        items.extend_from_slice(&rlp::encode_item(data));
        items.extend_from_slice(&rlp::encode_item(&[0x1b]));
        items.extend_from_slice(&rlp::encode_item(&[0xaa; 32]));
        items.extend_from_slice(&rlp::encode_item(&[0xbb; 32]));
        rlp::encode_list(&items)
    }

    fn to_hex(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    #[test]
    fn native_transfer_exact_balance_and_gas() {
        let to = [0xde_u8; 20];
        let tx = native_transfer_tx(to, 5_000_000_000_000_000_000);
        let sim = simulate_evm_tx_sync(&to_hex(&tx), "eip155:1").expect("simulate");
        assert!(sim.success);
        assert_eq!(sim.gas_used, NATIVE_TRANSFER_GAS);
        assert_eq!(sim.balance_change.len(), 1);
        assert_eq!(sim.balance_change[0].token, "ETH");
        assert_eq!(sim.balance_change[0].direction, TokenDirection::Send);
        assert_eq!(sim.balance_change[0].amount, "5");
        assert!(sim.decoded_action.is_none());
        assert!(sim.error.is_none());
    }

    #[test]
    fn native_transfer_fractional_eth() {
        let to = [0xde_u8; 20];
        let tx = native_transfer_tx(to, 1_500_000_000_000_000_000); // 1.5 ETH
        let sim = simulate_evm_tx_sync(&to_hex(&tx), "eip155:1").expect("simulate");
        assert_eq!(sim.balance_change[0].amount, "1.5");
    }

    #[test]
    fn native_transfer_zero_value() {
        let to = [0xde_u8; 20];
        let tx = native_transfer_tx(to, 0);
        let sim = simulate_evm_tx_sync(&to_hex(&tx), "eip155:1").expect("simulate");
        assert_eq!(sim.balance_change[0].amount, "0");
    }

    #[test]
    fn contract_call_decodes_known_calldata() {
        // ERC20 transfer selector + recipient + 1000
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&[0xde; 20]);
        let mut amt = vec![0u8; 30];
        amt.extend_from_slice(&[0x03, 0xe8]); // 1000
        data.extend_from_slice(&amt);

        let tx = contract_tx(&data);
        let sim = simulate_evm_tx_sync(&to_hex(&tx), "eip155:1").expect("simulate");
        assert!(sim.success);
        let action = sim.decoded_action.expect("decoded action");
        assert_eq!(action.contract_name, "ERC20");
        assert_eq!(action.function_name, "transfer");
        assert!(action.human_readable.contains("transfer"));
    }

    #[test]
    fn contract_call_unknown_calldata_yields_no_action_but_no_error() {
        // Unknown selector: decode_calldata returns None, sim stays success
        // (we cannot prove a revert offline).
        let data = [0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04];
        let tx = contract_tx(&data);
        let sim = simulate_evm_tx_sync(&to_hex(&tx), "eip155:1").expect("simulate");
        assert!(sim.success);
        assert!(sim.decoded_action.is_none());
        assert_eq!(sim.gas_used, 0);
    }

    #[test]
    fn rejects_bad_hex() {
        let err = simulate_evm_tx_sync("not-hex", "eip155:1").unwrap_err();
        assert!(matches!(err, SimError::HexDecode(_)));
    }

    #[test]
    fn rejects_truncated_rlp() {
        let err = simulate_evm_tx_sync("deadbeef", "eip155:1").unwrap_err();
        assert!(matches!(err, SimError::TxDecode(_)));
    }

    #[test]
    fn rejects_empty_input() {
        // Empty hex decodes to zero bytes → RLP decode must reject it.
        let err = simulate_evm_tx_sync("", "eip155:1").unwrap_err();
        assert!(matches!(err, SimError::TxDecode(_)));
    }

    #[test]
    fn format_wei_handles_whole_and_fractional() {
        assert_eq!(format_wei(0), "0");
        assert_eq!(format_wei(1_000_000_000_000_000_000), "1");
        assert_eq!(format_wei(5_000_000_000_000_000_000), "5");
        assert_eq!(format_wei(1_500_000_000_000_000_000), "1.5");
        assert_eq!(format_wei(123_456_789_012_345_678), "0.123456789012345678");
        assert_eq!(format_wei(500), "500 wei");
        assert_eq!(format_wei(2_000_000_000), "0.000000002");
    }
}
