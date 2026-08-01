use alloy_primitives::{Address, U256};
use oc_core::approval::DecodedAction;

use crate::abi_cache;

/// ABI-decode raw EVM calldata into a [`DecodedAction`].
///
/// Returns `None` when the 4-byte selector is unknown or the calldata is too
/// short (< 4 bytes).
pub fn decode_calldata(calldata: &[u8]) -> Option<DecodedAction> {
    if calldata.len() < 4 {
        return None;
    }
    let selector: [u8; 4] = [calldata[0], calldata[1], calldata[2], calldata[3]];
    let func = abi_cache::lookup(&selector)?;
    let param_data = &calldata[4..];

    let args = decode_params(param_data, &func.inputs);
    let human_readable = format_hr(&func.name, &func.inputs, &args);

    Some(DecodedAction {
        contract_name: func.contract_name,
        function_name: func.name,
        args,
        human_readable,
    })
}

/// Decode ABI-encoded parameters from fixed 32-byte slots.
///
/// # Limitations
///
/// This decoder only supports **static ABI types** (address, uint256, bool,
/// etc.).  Dynamic types (`bytes`, `string`, `T[]`) are NOT supported because
/// they use offset pointers in the encoding.  For the current use case
/// (ERC-20 `transfer` / `approve`), all parameters are static types.
///
/// If you need to decode dynamic types, use a full ABI decoder (e.g.
/// `ethabi`).
fn decode_params(data: &[u8], inputs: &[abi_cache::AbiParam]) -> serde_json::Value {
    let mut args = serde_json::Map::new();
    for (i, input) in inputs.iter().enumerate() {
        let offset = i * 32;
        let value = if offset + 32 > data.len() {
            serde_json::Value::Null
        } else {
            decode_single(data, offset, &input.ty)
        };
        args.insert(input.name.clone(), value);
    }
    serde_json::Value::Object(args)
}

fn decode_single(data: &[u8], offset: usize, ty: &str) -> serde_json::Value {
    if offset + 32 > data.len() {
        return serde_json::Value::String(format!(
            "error: insufficient data for {ty}: need 32 bytes at offset {offset}, have {}",
            data.len().saturating_sub(offset)
        ));
    }
    let word = &data[offset..offset + 32];
    match ty {
        "address" => {
            let addr = Address::from_slice(&word[12..32]);
            serde_json::Value::String(format!("{addr:?}"))
        }
        "uint256" | "int256" => {
            let val = U256::from_be_slice(word);
            serde_json::Value::String(val.to_string())
        }
        "uint160" => {
            let val = U256::from_be_slice(word);
            serde_json::Value::String(val.to_string())
        }
        "uint128" => {
            let val = U256::from_be_slice(word);
            serde_json::Value::String(val.to_string())
        }
        "uint64" => {
            let val = U256::from_be_slice(word);
            serde_json::Value::String(val.to_string())
        }
        "uint32" | "uint24" | "uint16" | "uint8" => {
            let val = U256::from_be_slice(word);
            serde_json::Value::String(val.to_string())
        }
        "bool" => {
            let val = U256::from_be_slice(word);
            serde_json::Value::Bool(!val.is_zero())
        }
        _ => {
            // bytes, dynamic types, tuples — just dump the raw word
            serde_json::Value::String(format!("0x{}", hex::encode(word)))
        }
    }
}

fn format_hr(fn_name: &str, inputs: &[abi_cache::AbiParam], args: &serde_json::Value) -> String {
    let mut parts = Vec::with_capacity(inputs.len());
    for input in inputs {
        let val = args.get(&input.name).map_or_else(
            || "?".into(),
            |v| match v {
                serde_json::Value::String(s) => {
                    if input.ty == "address" {
                        shorten_address(s)
                    } else {
                        s.clone()
                    }
                }
                serde_json::Value::Bool(b) => b.to_string(),
                _ => v.to_string(),
            },
        );
        parts.push(format!("{}={}", input.name, val));
    }
    if parts.is_empty() {
        fn_name.to_string()
    } else {
        format!("{}({})", fn_name, parts.join(", "))
    }
}

fn shorten_address(addr: &str) -> String {
    let stripped = addr.strip_prefix("0x").unwrap_or(addr);
    if stripped.len() > 10 {
        format!("0x{}…{}", &stripped[..4], &stripped[stripped.len() - 4..])
    } else {
        addr.to_string()
    }
}

/// Decode calldata from a hex string (with or without `0x` prefix).
pub fn decode_calldata_hex(hex_str: &str) -> Option<DecodedAction> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).ok()?;
    decode_calldata(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_erc20_transfer() {
        // transfer(0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef, 1000)
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        // address: 0x000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
        calldata.extend_from_slice(&[0u8; 12]);
        calldata
            .extend_from_slice(&hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap());
        // uint256: 1000 = 0x03e8
        calldata.extend_from_slice(&[0u8; 30]);
        calldata.extend_from_slice(&[0x03, 0xe8]);

        let result = decode_calldata(&calldata);
        assert!(result.is_some());
        let action = result.unwrap();
        assert_eq!(action.contract_name, "ERC20");
        assert_eq!(action.function_name, "transfer");
        assert!(action.human_readable.contains("transfer("));
        assert!(action.human_readable.contains("1000"));
    }

    #[test]
    fn unknown_calldata_returns_none() {
        let calldata = [0xff, 0xff, 0xff, 0xff, 0x00];
        assert!(decode_calldata(&calldata).is_none());
    }

    #[test]
    fn too_short_returns_none() {
        assert!(decode_calldata(&[0xa9, 0x05]).is_none());
        assert!(decode_calldata(&[]).is_none());
    }

    #[test]
    fn decode_erc20_approve() {
        // approve(0x1111111111111111111111111111111111111111, 500)
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]); // approve selector
        calldata.extend_from_slice(&[0u8; 12]);
        calldata
            .extend_from_slice(&hex::decode("1111111111111111111111111111111111111111").unwrap());
        calldata.extend_from_slice(&[0u8; 30]);
        calldata.extend_from_slice(&[0x01, 0xf4]); // 500

        let result = decode_calldata(&calldata);
        assert!(result.is_some());
        let action = result.unwrap();
        assert_eq!(action.function_name, "approve");
        assert!(action.human_readable.contains("500"));
    }

    #[test]
    fn decode_from_hex_string() {
        let hex = "0xa9059cbb000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000000000000001";
        let result = decode_calldata_hex(hex);
        assert!(result.is_some());
        assert_eq!(result.unwrap().function_name, "transfer");
    }

    #[test]
    fn empty_function_works() {
        // totalSupply() = 0x18160ddd, no params
        let calldata = [0x18, 0x16, 0x0d, 0xdd];
        let result = decode_calldata(&calldata);
        assert!(result.is_some());
        let action = result.unwrap();
        assert_eq!(action.function_name, "totalSupply");
        assert_eq!(action.human_readable, "totalSupply");
    }

    #[test]
    fn human_readable_formatting() {
        // transfer with a specific address
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        calldata.extend_from_slice(&[0u8; 12]);
        calldata
            .extend_from_slice(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap());
        calldata.extend_from_slice(&[0u8; 31]);
        calldata.push(0x64); // 100

        let action = decode_calldata(&calldata).unwrap();
        assert!(action.human_readable.starts_with("transfer("));
        assert!(action.human_readable.contains("100"));
    }
}
