//! `onecipher send` — cast-style ERC-20 transfer.
//!
//! Builds an unsigned EIP-1559 transaction for `token.transfer(to, amount)`,
//! signs it with the OneCipher wallet, and broadcasts it over the given RPC.
//! This mirrors `cast send <token> "transfer(address,uint256)" <to> <amount>`
//! from the Foundry CLI, but uses the OneCipher vault for key custody.

use hpx::Client;
use oc_core::ChainType;
use oc_signer::{
    rlp::{encode_bytes, encode_list},
    signer_for_chain,
};
use serde_json::{Value, json};
use tokio::runtime::Runtime;

use crate::{CliError, audit, commands, parse_chain};

/// ERC-20 `transfer(address,uint256)` function selector.
const ERC20_TRANSFER_SELECTOR: &str = "a9059cbb";

/// Run the cast-style token transfer.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    chain_str: &str,
    wallet_name: &str,
    to: &str,
    token: &str,
    amount: &str,
    rpc_url: &str,
    index: u32,
    gas_limit: Option<u64>,
    json_output: bool,
) -> Result<(), CliError> {
    let chain = parse_chain(chain_str)?;
    if chain.chain_type != ChainType::Evm {
        return Err(CliError::InvalidArgs(format!(
            "send supports EVM chains only (got '{chain_str}')"
        )));
    }

    let wallet = if wallet_name.trim().is_empty() { "default" } else { wallet_name };
    let recipient = parse_evm_address(to)?;
    let token_addr = parse_evm_address(token)?;
    let amount_value: u128 = amount.trim().parse().map_err(|_| {
        CliError::InvalidArgs(format!("invalid amount '{amount}' (expect integer base units)"))
    })?;

    let rpc = rpc_url.trim();

    // API tokens are not supported yet; the owner passphrase is used.
    if let Some(passphrase) = commands::peek_passphrase() &&
        oc_core::Credential::parse(&passphrase).is_token()
    {
        return Err(CliError::InvalidArgs(
            "send requires the owner passphrase (API tokens are not supported yet)".into(),
        ));
    }

    let rt =
        Runtime::new().map_err(|error| CliError::InvalidArgs(format!("tokio runtime: {error}")))?;

    // Read on-chain parameters.
    let chain_id =
        rpc_hex_to_u64(&rt, rpc, "eth_chainId", Value::Array(Vec::new()), "eth_chainId")?;
    let signer = signer_for_chain(ChainType::Evm);
    // Resolve the signing key: empty passphrase first (dev wallets), then the
    // ONECIPHER_PASSPHRASE value.
    let key = oc_wallet::decrypt_signing_key(wallet, ChainType::Evm, b"", Some(index), None)
        .or_else(|_| {
            let passphrase = commands::peek_passphrase().unwrap_or_default();
            oc_wallet::decrypt_signing_key(
                wallet,
                ChainType::Evm,
                passphrase.as_bytes(),
                Some(index),
                None,
            )
        })?;
    let from = signer.derive_address(key.expose())?;

    let nonce = rpc_hex_to_u64(
        &rt,
        rpc,
        "eth_getTransactionCount",
        json!([from, "pending"]),
        "eth_getTransactionCount",
    )?;
    let priority = rpc_hex_to_u64(
        &rt,
        rpc,
        "eth_maxPriorityFeePerGas",
        Value::Array(Vec::new()),
        "eth_maxPriorityFeePerGas",
    )?;
    let gas_price =
        rpc_hex_to_u64(&rt, rpc, "eth_gasPrice", Value::Array(Vec::new()), "eth_gasPrice")?;
    let max_fee_per_gas = gas_price.max(priority);
    let max_priority_fee_per_gas = priority.min(max_fee_per_gas);

    let data = build_transfer_data(&recipient, amount_value)?;

    let gas_limit = match gas_limit {
        Some(value) => value,
        None => rpc_hex_to_u64(
            &rt,
            rpc,
            "eth_estimateGas",
            json!([{ "from": from, "to": format!("0x{token_addr}"), "data": format!("0x{}", hex::encode(&data)) }]),
            "eth_estimateGas",
        )?,
    };

    // Build the unsigned EIP-1559 typed transaction:
    //   0x02 || RLP([chain_id, nonce, max_priority_fee, max_fee, gas, to, value, data,
    // access_list])
    let mut items = Vec::new();
    items.extend_from_slice(&encode_bytes(&rlp_uint(chain_id)));
    items.extend_from_slice(&encode_bytes(&rlp_uint(nonce)));
    items.extend_from_slice(&encode_bytes(&rlp_uint(max_priority_fee_per_gas)));
    items.extend_from_slice(&encode_bytes(&rlp_uint(max_fee_per_gas)));
    items.extend_from_slice(&encode_bytes(&rlp_uint(gas_limit)));
    let token_addr_bytes = hex::decode(&token_addr)
        .map_err(|e| CliError::InvalidArgs(format!("invalid token address hex: {e}")))?;
    items.extend_from_slice(&encode_bytes(&token_addr_bytes));
    items.extend_from_slice(&encode_bytes(&[])); // value = 0
    items.extend_from_slice(&encode_bytes(&data));
    items.extend_from_slice(&encode_list(&[])); // empty access list

    let mut unsigned_tx = vec![0x02];
    unsigned_tx.extend_from_slice(&encode_list(&items));

    let result =
        oc_wallet::sign_encode_and_broadcast(key.expose(), chain_str, &unsigned_tx, Some(rpc))?;

    if json_output {
        let output = json!({
            "tx_hash": result.tx_hash,
            "chain": chain_str,
            "chain_id": chain_id,
            "token": format!("0x{token_addr}"),
            "to": format!("0x{recipient}"),
            "from": from,
            "amount": amount_value.to_string(),
            "nonce": nonce,
            "gas_limit": gas_limit,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", result.tx_hash);
    }

    audit::log_broadcast(wallet, chain_str, &result.tx_hash);
    Ok(())
}

/// Parse a `0x`-prefixed EVM address into lowercase hex without the prefix.
fn parse_evm_address(value: &str) -> Result<String, CliError> {
    let hex = value.trim().strip_prefix("0x").unwrap_or_else(|| value.trim());
    if hex.len() != 40 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CliError::InvalidArgs(format!(
            "invalid EVM address '{value}' (expected 0x + 40 hex chars)"
        )));
    }
    Ok(hex.to_ascii_lowercase())
}

/// Build `transfer(address,uint256)` calldata for the given recipient/amount.
fn build_transfer_data(to: &str, amount: u128) -> Result<Vec<u8>, CliError> {
    let mut data = hex::decode(ERC20_TRANSFER_SELECTOR)
        .map_err(|_| CliError::InvalidArgs("bad selector".into()))?;

    let mut to_padded = vec![0u8; 12];
    to_padded.extend_from_slice(
        &hex::decode(to).map_err(|e| CliError::InvalidArgs(format!("bad recipient hex: {e}")))?,
    );
    data.extend_from_slice(&to_padded);

    let mut amount_bytes = [0u8; 32];
    amount_bytes[16..].copy_from_slice(&amount.to_be_bytes());
    data.extend_from_slice(&amount_bytes);
    Ok(data)
}

/// Minimal big-endian bytes for RLP integer encoding (empty for zero).
fn rlp_uint(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

/// Perform an EVM JSON-RPC call.
fn rpc_call(rt: &Runtime, rpc_url: &str, method: &str, params: Value) -> Result<Value, CliError> {
    rt.block_on(async {
        let client = Client::new();
        let body = json!({ "jsonrpc": "2.0", "method": method, "params": params, "id": 1 });
        let response = client
            .post(rpc_url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|error| CliError::InvalidArgs(format!("rpc '{method}' failed: {error}")))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(CliError::InvalidArgs(format!(
                "rpc '{method}' failed (HTTP {status}): {text}"
            )));
        }
        let text = response.text().await.map_err(|error| {
            CliError::InvalidArgs(format!("rpc '{method}' read failed: {error}"))
        })?;
        let parsed: Value = serde_json::from_str(&text)
            .map_err(|error| CliError::InvalidArgs(format!("rpc '{method}' bad JSON: {error}")))?;
        if let Some(error) = parsed.get("error") {
            return Err(CliError::InvalidArgs(format!("rpc '{method}' error: {error}")));
        }
        Ok(parsed.get("result").cloned().unwrap_or(Value::Null))
    })
}

/// Read a hex quantity result from a JSON-RPC call.
fn rpc_hex_to_u64(
    rt: &Runtime,
    rpc_url: &str,
    method: &str,
    params: Value,
    label: &str,
) -> Result<u64, CliError> {
    let result = rpc_call(rt, rpc_url, method, params)?;
    let hex = result
        .as_str()
        .ok_or_else(|| CliError::InvalidArgs(format!("'{label}' returned non-string: {result}")))?;
    u64::from_str_radix(hex.trim_start_matches("0x"), 16)
        .map_err(|error| CliError::InvalidArgs(format!("'{label}' bad hex '{hex}': {error}")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parses_evm_addresses() {
        let addr = "0x00B8E3e3d589577bAeAbbE0f72993e5F72e82f00";
        assert_eq!(parse_evm_address(addr).unwrap(), addr[2..].to_ascii_lowercase());
        assert!(parse_evm_address("0x1234").is_err());
        assert!(parse_evm_address("0xGGG8E3e3d589577bAeAbbE0f72993e5F72e82f00").is_err());
    }

    #[test]
    fn builds_transfer_calldata() {
        let to = "00B8E3e3d589577bAeAbbE0f72993e5F72e82f00".to_string();
        let data = build_transfer_data(&to, 1_000_000).unwrap();
        assert_eq!(&data[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(data.len(), 4 + 32 + 32);
        // Recipient at word boundary.
        assert_eq!(&data[4..16], &[0u8; 12]);
        assert_eq!(&data[16..36], &hex::decode(&to).unwrap()[..]);
        // Amount as the last word.
        assert_eq!(&data[36..52], &[0u8; 16]);
        assert_eq!(u128::from_be_bytes(data[52..68].try_into().unwrap()), 1_000_000);
    }

    #[test]
    fn rlp_uint_encodes_minimally() {
        assert_eq!(rlp_uint(0), Vec::<u8>::new());
        assert_eq!(rlp_uint(1), vec![1]);
        assert_eq!(rlp_uint(0x4cef52), vec![0x4c, 0xef, 0x52]);
    }
}
