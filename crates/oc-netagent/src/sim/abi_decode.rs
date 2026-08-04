use alloy_dyn_abi::{DynSolType, DynSolValue};
use oc_core::approval::DecodedAction;

use super::abi_cache;

/// ABI-decode raw EVM calldata into a [`DecodedAction`].
///
/// Returns `None` when the 4-byte selector is unknown or the calldata is too
/// short (< 4 bytes).
pub fn decode_calldata(calldata: &[u8]) -> Option<DecodedAction> {
    decode_calldata_hinted(calldata, None)
}

/// Decode calldata with an optional contract-type hint for selector disambiguation.
///
/// When `known_contract` is `Some("ERC20")` and the selector has multiple
/// candidates, the ERC20 resolution is preferred. Otherwise the curated-first
/// entry is used (see [`abi_cache::disambiguate`]).
pub fn decode_calldata_hinted(
    calldata: &[u8],
    known_contract: Option<&str>,
) -> Option<DecodedAction> {
    if calldata.len() < 4 {
        return None;
    }
    let selector: [u8; 4] = [calldata[0], calldata[1], calldata[2], calldata[3]];
    let candidates = abi_cache::lookup(&selector);
    let func = abi_cache::disambiguate(candidates, known_contract)?;
    let param_data = &calldata[4..];

    let args = decode_params(param_data, &func.inputs);

    // When the selector has multiple possible interpretations, annotate the
    // human-readable label so the operator can distinguish ERC20::approve
    // from ERC721::approve without needing to check the target contract.
    let has_ambiguity = candidates.len() > 1;
    let human_readable =
        format_hr(&func.name, &func.contract_name, has_ambiguity, &func.inputs, &args);

    Some(DecodedAction {
        contract_name: func.contract_name.clone(),
        function_name: func.name.clone(),
        args,
        human_readable,
    })
}

/// Decode ABI-encoded parameters.
///
/// Uses `alloy-dyn-abi` so that **dynamic types** (`bytes`, `string`, `T[]`,
/// tuples) are decoded correctly rather than being reported as the raw
/// offset-pointer word. This matters for user-facing approval prompts: a
/// `swapExactTokensForTokens(path: address[])` call must display the actual
/// swap path, not a meaningless offset.
///
/// Decoding is performed over the whole parameter tuple at once, because the
/// ABI head/tail layout means individual parameters cannot be decoded in
/// isolation. If the tuple fails to decode (truncated calldata, ABI mismatch),
/// we fall back to a per-parameter best-effort decode so the operator still
/// sees partial information instead of nothing.
fn decode_params(data: &[u8], inputs: &[abi_cache::AbiParam]) -> serde_json::Value {
    let mut args = serde_json::Map::new();

    // Resolve every declared parameter type up front. An unknown/unparseable
    // type poisons the whole-tuple decode, so we degrade to best-effort.
    let resolved: Option<Vec<DynSolType>> =
        inputs.iter().map(|p| p.ty.parse::<DynSolType>().ok()).collect();

    if let Some(types) = resolved {
        if types.is_empty() {
            return serde_json::Value::Object(args);
        }
        let tuple = DynSolType::Tuple(types);
        if let Ok(DynSolValue::Tuple(values)) = tuple.abi_decode_params(data) {
            for (input, value) in inputs.iter().zip(values.iter()) {
                args.insert(input.name.clone(), sol_value_to_json(value));
            }
            return serde_json::Value::Object(args);
        }
    }

    // Fallback: best-effort static-slot read. Only meaningful for static
    // types, but better than emitting nothing when calldata is malformed.
    for (i, input) in inputs.iter().enumerate() {
        let offset = i * 32;
        let value = if offset + 32 > data.len() {
            serde_json::Value::String(format!(
                "error: insufficient data for {}: need 32 bytes at offset {offset}, have {}",
                input.ty,
                data.len().saturating_sub(offset)
            ))
        } else {
            decode_static_word(&data[offset..offset + 32], &input.ty)
        };
        args.insert(input.name.clone(), value);
    }
    serde_json::Value::Object(args)
}

/// Convert a decoded [`DynSolValue`] into the JSON shape the approval UI
/// expects.
///
/// Numbers are rendered as decimal **strings** (not JSON numbers) because
/// `uint256` exceeds the range of an IEEE-754 double and every downstream
/// consumer must see the exact value.
fn sol_value_to_json(value: &DynSolValue) -> serde_json::Value {
    match value {
        DynSolValue::Address(a) => serde_json::Value::String(format!("{a:?}")),
        DynSolValue::Bool(b) => serde_json::Value::Bool(*b),
        DynSolValue::Uint(v, _) => serde_json::Value::String(v.to_string()),
        DynSolValue::Int(v, _) => serde_json::Value::String(v.to_string()),
        DynSolValue::FixedBytes(b, size) => {
            serde_json::Value::String(format!("0x{}", hex::encode(&b.0[..*size])))
        }
        DynSolValue::Bytes(b) => serde_json::Value::String(format!("0x{}", hex::encode(b))),
        DynSolValue::String(s) => serde_json::Value::String(s.clone()),
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) => {
            serde_json::Value::Array(items.iter().map(sol_value_to_json).collect())
        }
        DynSolValue::Tuple(items) => {
            serde_json::Value::Array(items.iter().map(sol_value_to_json).collect())
        }
        DynSolValue::Function(f) => serde_json::Value::String(format!("0x{}", hex::encode(f.0))),
    }
}

/// Best-effort decode of a single 32-byte static word.
///
/// Only used on the fallback path when whole-tuple decoding fails.
fn decode_static_word(word: &[u8], ty: &str) -> serde_json::Value {
    debug_assert_eq!(word.len(), 32);
    match ty.parse::<DynSolType>() {
        Ok(
            t @ (DynSolType::Address | DynSolType::Bool | DynSolType::Uint(_) | DynSolType::Int(_)),
        ) => t.abi_decode(word).map_or_else(
            |_| serde_json::Value::String(format!("0x{}", hex::encode(word))),
            |v| sol_value_to_json(&v),
        ),
        _ => serde_json::Value::String(format!("0x{}", hex::encode(word))),
    }
}

fn format_hr(
    fn_name: &str,
    contract_name: &str,
    ambiguous: bool,
    inputs: &[abi_cache::AbiParam],
    args: &serde_json::Value,
) -> String {
    let mut parts = Vec::with_capacity(inputs.len());
    for input in inputs {
        let val = args.get(&input.name).map_or_else(|| "?".into(), |v| render_value(v, &input.ty));
        parts.push(format!("{}={}", input.name, val));
    }
    // When the selector is ambiguous, prefix with the contract name so the
    // operator sees ERC20::approve or ERC721::approve rather than an
    // unqualified name that might be wrong for the target contract.
    let prefix = if ambiguous { format!("{contract_name}::") } else { String::new() };
    if parts.is_empty() {
        format!("{prefix}{fn_name}")
    } else {
        format!("{prefix}{fn_name}({})", parts.join(", "))
    }
}

/// Render a decoded value for the single-line human-readable summary.
///
/// Addresses are shortened; arrays are rendered as `[a, b, c]` with each
/// element rendered by the element type so `address[]` shortens correctly.
fn render_value(v: &serde_json::Value, ty: &str) -> String {
    match v {
        serde_json::Value::String(s) => {
            if ty == "address" {
                shorten_address(s)
            } else {
                s.clone()
            }
        }
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Array(items) => {
            let elem_ty = ty.strip_suffix("[]").unwrap_or("");
            let rendered: Vec<String> = items.iter().map(|i| render_value(i, elem_ty)).collect();
            format!("[{}]", rendered.join(", "))
        }
        _ => v.to_string(),
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

    /// Regression: dynamic `address[]` used to be rendered as its raw
    /// offset-pointer word (e.g. `0x…00a0`), which is meaningless — and
    /// dangerous — in an approval prompt. It must now show the real path.
    #[test]
    fn decode_dynamic_address_array_swap_path() {
        // swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
        // selector 0x38ed1739
        let a1 = "1111111111111111111111111111111111111111";
        let a2 = "2222222222222222222222222222222222222222";
        let to = "3333333333333333333333333333333333333333";

        let mut cd = Vec::new();
        cd.extend_from_slice(&[0x38, 0xed, 0x17, 0x39]);

        let word = |hexstr: &str| {
            let mut w = vec![0u8; 32];
            let b = hex::decode(hexstr).unwrap();
            w[32 - b.len()..].copy_from_slice(&b);
            w
        };

        cd.extend_from_slice(&word("64")); // amountIn = 100
        cd.extend_from_slice(&word("01")); // amountOutMin = 1
        cd.extend_from_slice(&word("a0")); // offset to path = 160
        cd.extend_from_slice(&word(to)); // to
        cd.extend_from_slice(&word("02")); // deadline = 2
        // tail: path array
        cd.extend_from_slice(&word("02")); // length = 2
        cd.extend_from_slice(&word(a1));
        cd.extend_from_slice(&word(a2));

        let action = decode_calldata(&cd).expect("selector should resolve");
        assert_eq!(action.function_name, "swapExactTokensForTokens");

        let path = action.args.get("path").expect("path arg present");
        let arr = path.as_array().expect("path must decode as a JSON array");
        assert_eq!(arr.len(), 2, "path must have 2 hops, got {arr:?}");
        assert!(
            arr[0].as_str().unwrap().to_lowercase().contains("1111"),
            "first hop wrong: {arr:?}"
        );
        assert!(
            arr[1].as_str().unwrap().to_lowercase().contains("2222"),
            "second hop wrong: {arr:?}"
        );

        // The summary must render the array, not an offset word.
        assert!(
            action.human_readable.contains('['),
            "human_readable should render the array: {}",
            action.human_readable
        );
    }

    /// Truncated calldata must not panic and must still surface the function.
    #[test]
    fn truncated_calldata_degrades_gracefully() {
        let mut cd = vec![0xa9, 0x05, 0x9c, 0xbb];
        cd.extend_from_slice(&[0u8; 16]); // half a word only
        let action = decode_calldata(&cd).expect("selector still resolves");
        assert_eq!(action.function_name, "transfer");
    }

    #[test]
    fn uint256_max_is_exact_decimal_string() {
        // approve(spender, type(uint256).max) — the classic infinite approval.
        let mut cd = vec![0x09, 0x5e, 0xa7, 0xb3];
        cd.extend_from_slice(&[0u8; 12]);
        cd.extend_from_slice(&hex::decode("1111111111111111111111111111111111111111").unwrap());
        cd.extend_from_slice(&[0xffu8; 32]);

        let action = decode_calldata(&cd).unwrap();
        // NOTE: selector 0x095ea7b3 is shared by ERC20 `approve(address,uint256)`
        // and ERC721 `approve(address,uint256)`, so the resolved parameter name
        // depends on ABI load order. Assert on the decoded *value* instead.
        let uint_arg = action
            .args
            .as_object()
            .expect("args is an object")
            .values()
            .filter_map(serde_json::Value::as_str)
            .find(|s| !s.starts_with("0x"))
            .expect("a uint256 argument decoded as a decimal string");
        assert_eq!(
            uint_arg,
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }
}
